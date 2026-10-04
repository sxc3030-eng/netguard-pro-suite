# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""
Argus Vault V1 — triple-layered secrets store.

Layer 1 (data):  AES-256-GCM with a fresh per-secret nonce.
Layer 2 (key):   masterkey wrapped via Windows DPAPI on Windows; otherwise
                 wrapped via PBKDF2-HMAC-SHA256 (600k iterations) derived
                 from a passphrase.
Layer 3 (audit): TODO(V3) — append-only signed audit log out of scope for V1.

Storage: a single JSON file at ``argus_data/.vault/secrets.enc``.
``argus_data/`` is in .gitignore at the repo root.

Public API (module-level, no class needed for V1):
    vault_exists() -> bool
    vault_init(passphrase: Optional[str] = None) -> bool
    vault_set(key: str, value: str, owner: str = "system") -> None
    vault_get(key: str) -> Optional[str]
    vault_delete(key: str) -> bool
    vault_list() -> list[dict]                # metadata only — never values
    vault_rotate_masterkey(new_passphrase: Optional[str] = None) -> None

Security notes:
* Exception messages in this module are intentionally generic. Plaintext,
  passphrase, and master-key material are NEVER included in raised errors.
* Plaintext is best-effort overwritten with zeros after use. CPython ``str``
  objects are immutable and interned, so true zeroization is not guaranteed;
  use ``bytearray`` where possible. This is documented as a known limitation.
* TODO(V2): expose a local REST API (loopback only) for cross-process access.
* TODO(V3): write an append-only HMAC-signed audit log of every operation.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

VAULT_VERSION = 1
MASTERKEY_BYTES = 32          # AES-256
NONCE_BYTES = 12              # GCM standard nonce length
PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16
WRAP_DPAPI = "dpapi"
WRAP_PBKDF2 = "pbkdf2"


def _vault_root() -> Path:
    """Resolve vault root.

    Honours the ``ARGUS_VAULT_ROOT`` env var so tests can redirect storage
    via the ``tmp_path`` fixture. Otherwise falls back to ``argus_data/``
    next to this module.
    """
    override = os.environ.get("ARGUS_VAULT_ROOT")
    if override:
        return Path(override) / ".vault"
    return Path(__file__).resolve().parent / "argus_data" / ".vault"


def _vault_file() -> Path:
    return _vault_root() / "secrets.enc"


# --------------------------------------------------------------------------- #
# Custom exceptions — error messages stay generic on purpose
# --------------------------------------------------------------------------- #


class VaultError(Exception):
    """Base class for vault errors."""


class VaultNotInitializedError(VaultError):
    """Raised when an operation is attempted before ``vault_init``."""


class VaultAlreadyInitializedError(VaultError):
    """Raised by ``vault_init`` if a vault already exists (idempotent skip)."""


class VaultCorruptedError(VaultError):
    """Raised when the on-disk file fails to parse or decrypt."""


class VaultPassphraseRequiredError(VaultError):
    """Raised when a passphrase is needed but none was supplied."""


# --------------------------------------------------------------------------- #
# DPAPI helpers (Windows only) — silent fallback to PBKDF2 elsewhere
# --------------------------------------------------------------------------- #


def _dpapi_available() -> bool:
    if platform.system() != "Windows":
        return False
    try:
        import win32crypt  # noqa: F401  (import probe only)
    except Exception:
        return False
    return True


def _dpapi_protect(blob: bytes) -> bytes:
    import win32crypt  # local import — module may be absent on non-Windows

    # CryptProtectData returns a tuple (description, ciphertext); we drop the
    # description and store only the ciphertext blob.
    return win32crypt.CryptProtectData(blob, None, None, None, None, 0)


def _dpapi_unprotect(blob: bytes) -> bytes:
    import win32crypt

    _, plaintext = win32crypt.CryptUnprotectData(blob, None, None, None, 0)
    return plaintext


# --------------------------------------------------------------------------- #
# PBKDF2 helpers (cross-platform fallback)
# --------------------------------------------------------------------------- #


def _derive_kek(passphrase: str, salt: bytes,
                iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 32-byte key-encrypting-key from a passphrase."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=MASTERKEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    # ``derive`` consumes a bytes input; encode then best-effort scrub.
    pw_bytes = bytearray(passphrase.encode("utf-8"))
    try:
        return kdf.derive(bytes(pw_bytes))
    finally:
        for i in range(len(pw_bytes)):
            pw_bytes[i] = 0


def _pbkdf2_wrap(masterkey: bytes, passphrase: str) -> Dict[str, Any]:
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    kek = bytearray(_derive_kek(passphrase, salt))
    nonce = secrets.token_bytes(NONCE_BYTES)
    try:
        ct = AESGCM(bytes(kek)).encrypt(nonce, masterkey, None)
    finally:
        for i in range(len(kek)):
            kek[i] = 0
    return {
        "wrapped_key": base64.b64encode(nonce + ct).decode("ascii"),
        "wrap_method": WRAP_PBKDF2,
        "kdf_salt": base64.b64encode(salt).decode("ascii"),
        "kdf_iterations": PBKDF2_ITERATIONS,
    }


def _pbkdf2_unwrap(blob: Dict[str, Any], passphrase: str) -> bytes:
    try:
        salt = base64.b64decode(blob["kdf_salt"])
        iterations = int(blob.get("kdf_iterations", PBKDF2_ITERATIONS))
        wrapped = base64.b64decode(blob["wrapped_key"])
    except Exception as exc:
        raise VaultCorruptedError("vault wrap metadata invalid") from exc

    nonce, ct = wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:]
    kek = bytearray(_derive_kek(passphrase, salt, iterations))
    try:
        return AESGCM(bytes(kek)).decrypt(nonce, ct, None)
    except Exception as exc:
        # Do NOT include passphrase or any key material in the message.
        raise VaultCorruptedError("vault wrap decryption failed") from exc
    finally:
        for i in range(len(kek)):
            kek[i] = 0


# --------------------------------------------------------------------------- #
# File I/O
# --------------------------------------------------------------------------- #


def _read_vault_file() -> Dict[str, Any]:
    path = _vault_file()
    if not path.exists():
        raise VaultNotInitializedError("vault not initialized")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise VaultCorruptedError("vault file is not valid JSON") from exc
    except OSError as exc:
        raise VaultCorruptedError("vault file unreadable") from exc

    if not isinstance(data, dict) or data.get("version") != VAULT_VERSION:
        raise VaultCorruptedError("vault version unsupported or missing")
    if "wrapped_key" not in data or "wrap_method" not in data:
        raise VaultCorruptedError("vault header incomplete")
    if "secrets" not in data or not isinstance(data["secrets"], dict):
        raise VaultCorruptedError("vault body malformed")
    return data


def _write_vault_file(data: Dict[str, Any]) -> None:
    path = _vault_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


# --------------------------------------------------------------------------- #
# Master-key load (used by every read/write op)
# --------------------------------------------------------------------------- #


def _load_masterkey(data: Dict[str, Any],
                    passphrase: Optional[str]) -> bytes:
    method = data.get("wrap_method")
    if method == WRAP_DPAPI:
        if not _dpapi_available():
            raise VaultError(
                "vault was sealed with DPAPI but DPAPI is unavailable here"
            )
        try:
            wrapped = base64.b64decode(data["wrapped_key"])
        except Exception as exc:
            raise VaultCorruptedError("wrapped_key encoding invalid") from exc
        try:
            return _dpapi_unprotect(wrapped)
        except Exception as exc:
            raise VaultCorruptedError("DPAPI unwrap failed") from exc
    if method == WRAP_PBKDF2:
        if passphrase is None:
            # Headless / CI / service use: an explicit opt-in environment passphrase
            # (never set it on a shared machine; DPAPI is the default on Windows).
            passphrase = os.environ.get("ARGUS_VAULT_PASSPHRASE") or None
        if passphrase is None:
            raise VaultPassphraseRequiredError(
                "passphrase required to unlock this vault"
            )
        return _pbkdf2_unwrap(data, passphrase)
    raise VaultCorruptedError("unknown wrap_method")


def _wrap_masterkey(masterkey: bytes,
                    passphrase: Optional[str]) -> Dict[str, Any]:
    """Wrap a master key using DPAPI when possible, else PBKDF2."""
    if passphrase is None and _dpapi_available():
        wrapped = _dpapi_protect(masterkey)
        return {
            "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
            "wrap_method": WRAP_DPAPI,
        }
    if passphrase is None:
        raise VaultPassphraseRequiredError(
            "passphrase required: DPAPI unavailable on this platform"
        )
    return _pbkdf2_wrap(masterkey, passphrase)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def vault_exists() -> bool:
    """Return True if a vault file already exists on disk."""
    return _vault_file().exists()


def vault_init(passphrase: Optional[str] = None) -> bool:
    """Create a new empty vault. Idempotent: returns False if one already exists.

    If a passphrase is supplied, PBKDF2 wrapping is used regardless of platform.
    Otherwise, DPAPI is used when available (Windows); else this raises
    ``VaultPassphraseRequiredError``.
    """
    if vault_exists():
        return False

    masterkey = bytearray(secrets.token_bytes(MASTERKEY_BYTES))
    try:
        wrap = _wrap_masterkey(bytes(masterkey), passphrase)
    finally:
        for i in range(len(masterkey)):
            masterkey[i] = 0

    payload: Dict[str, Any] = {
        "version": VAULT_VERSION,
        **wrap,
        "secrets": {},
    }
    _write_vault_file(payload)
    return True


def vault_set(key: str, value: str, owner: str = "system",
              passphrase: Optional[str] = None) -> None:
    """Encrypt ``value`` under ``key`` with metadata ``owner``."""
    if not isinstance(key, str) or not key:
        raise ValueError("key must be a non-empty string")
    if not isinstance(value, str):
        raise ValueError("value must be a string")

    data = _read_vault_file()
    masterkey = bytearray(_load_masterkey(data, passphrase))
    try:
        nonce = secrets.token_bytes(NONCE_BYTES)
        # Encode plaintext into a bytearray we can scrub.
        pt = bytearray(value.encode("utf-8"))
        try:
            ct = AESGCM(bytes(masterkey)).encrypt(nonce, bytes(pt), None)
        finally:
            for i in range(len(pt)):
                pt[i] = 0
    finally:
        for i in range(len(masterkey)):
            masterkey[i] = 0

    data["secrets"][key] = {
        "ciphertext_b64": base64.b64encode(ct).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "owner": owner,
    }
    _write_vault_file(data)
    # TODO(V3): append audit-log entry for SET.


def vault_get(key: str, passphrase: Optional[str] = None) -> Optional[str]:
    """Return decrypted value for ``key``, or None if absent."""
    data = _read_vault_file()
    entry = data["secrets"].get(key)
    if entry is None:
        return None

    try:
        nonce = base64.b64decode(entry["nonce_b64"])
        ct = base64.b64decode(entry["ciphertext_b64"])
    except Exception as exc:
        raise VaultCorruptedError("secret encoding invalid") from exc

    masterkey = bytearray(_load_masterkey(data, passphrase))
    try:
        try:
            plaintext_bytes = AESGCM(bytes(masterkey)).decrypt(nonce, ct, None)
        except Exception as exc:
            raise VaultCorruptedError("secret decryption failed") from exc
    finally:
        for i in range(len(masterkey)):
            masterkey[i] = 0

    # Best-effort scrub: decode then drop the bytes reference. Note: the
    # returned ``str`` is immutable and may be retained by the interpreter;
    # this is an acknowledged Python limitation.
    try:
        return plaintext_bytes.decode("utf-8")
    finally:
        # plaintext_bytes is bytes (immutable); the buffer is unreachable
        # after we leave this scope. Reassigning is the most we can do.
        plaintext_bytes = b"\x00" * len(plaintext_bytes)  # noqa: F841


def vault_delete(key: str) -> bool:
    """Remove ``key`` if present. Returns True iff it existed."""
    data = _read_vault_file()
    if key not in data["secrets"]:
        return False
    del data["secrets"][key]
    _write_vault_file(data)
    # TODO(V3): append audit-log entry for DELETE.
    return True


def vault_list() -> List[Dict[str, Any]]:
    """Return metadata for every secret. NEVER includes the value."""
    data = _read_vault_file()
    out: List[Dict[str, Any]] = []
    for name, entry in data["secrets"].items():
        out.append({
            "name": name,
            "created_at": entry.get("created_at"),
            "owner": entry.get("owner"),
        })
    return out


def vault_rotate_masterkey(new_passphrase: Optional[str] = None,
                           old_passphrase: Optional[str] = None) -> None:
    """Generate a new master key and re-encrypt every secret under it.

    The new key is wrapped via the same rules as ``vault_init``: DPAPI when
    available and no passphrase is supplied, otherwise PBKDF2 with the
    provided ``new_passphrase``.
    """
    data = _read_vault_file()
    old_master = bytearray(_load_masterkey(data, old_passphrase))
    new_master = bytearray(secrets.token_bytes(MASTERKEY_BYTES))
    try:
        old_aead = AESGCM(bytes(old_master))
        new_aead = AESGCM(bytes(new_master))
        rewrapped: Dict[str, Dict[str, Any]] = {}
        for name, entry in data["secrets"].items():
            try:
                nonce = base64.b64decode(entry["nonce_b64"])
                ct = base64.b64decode(entry["ciphertext_b64"])
            except Exception as exc:
                raise VaultCorruptedError(
                    "secret encoding invalid during rotation"
                ) from exc
            try:
                pt = old_aead.decrypt(nonce, ct, None)
            except Exception as exc:
                raise VaultCorruptedError(
                    "secret decryption failed during rotation"
                ) from exc

            new_nonce = secrets.token_bytes(NONCE_BYTES)
            try:
                new_ct = new_aead.encrypt(new_nonce, pt, None)
            finally:
                # pt is immutable bytes — reassignment is best-effort scrub.
                pt = b"\x00" * len(pt)  # noqa: F841

            rewrapped[name] = {
                "ciphertext_b64": base64.b64encode(new_ct).decode("ascii"),
                "nonce_b64": base64.b64encode(new_nonce).decode("ascii"),
                "created_at": entry.get("created_at"),
                "owner": entry.get("owner"),
            }

        wrap = _wrap_masterkey(bytes(new_master), new_passphrase)
    finally:
        for i in range(len(old_master)):
            old_master[i] = 0
        for i in range(len(new_master)):
            new_master[i] = 0

    new_payload: Dict[str, Any] = {
        "version": VAULT_VERSION,
        **wrap,
        "secrets": rewrapped,
    }
    _write_vault_file(new_payload)
    # TODO(V3): append audit-log entry for ROTATE.
