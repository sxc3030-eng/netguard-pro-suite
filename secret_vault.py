# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
#
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""
Secret Vault — triple-encryption credential store.

Layer 1 (DPAPI):       protects the wrapped Data Encryption Key against
                       another Windows user on the same machine.
Layer 2 (Keyring):     a 32-byte "blind" lives in Windows Credential Manager
                       — never on disk — and is XOR'd into the wrap-key chain.
Layer 3 (Argon2id):    a master password derives KEK_master via Argon2id
                       (memory-hard) and unwraps the wrap-key.

All three layers must be defeated to extract a secret. See
``docs/secret_vault_spec.md`` for the full threat model and key chain.

Public API:
    vault = SecretVault(vault_root=None, idle_timeout_minutes=15)
    vault.exists()                          -> bool
    vault.init(master)                      -> None
    vault.unlock(master)                    -> None
    vault.lock()                            -> None
    vault.is_unlocked()                     -> bool
    vault.set(name, secret, metadata=None)  -> None
    vault.get(name)                         -> Optional[str]
    vault.list()                            -> List[Dict[str, Any]]
    vault.delete(name)                      -> bool
    vault.change_master(old, new)           -> None
    vault.audit_log()                       -> List[Dict[str, Any]]
    vault.migrate_from_settings_json(path, master) -> int

Optional deps (gracefully degraded with clear errors):
    argon2-cffi   (Layer 3)  REQUIRED
    keyring       (Layer 2)  REQUIRED
    pywin32       (Layer 1)  optional — falls back to "no DPAPI" with warning

Plaintext secrets are NEVER logged or written to the audit log. KEK material
is held in ``bytearray`` and best-effort zeroized on lock(). True zeroization
is impossible on CPython due to GC; this is a documented limitation.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import platform
import re
import secrets as _stdlib_secrets
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Hard dependency: cryptography. We refuse to even import without it.
# --------------------------------------------------------------------------- #
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------- #
# Soft dependencies: detected at construction time, errors raised lazily.
# --------------------------------------------------------------------------- #
try:
    from argon2.low_level import Type as _Argon2Type, hash_secret_raw as _argon2_hash_raw
    _HAS_ARGON2 = True
except Exception:  # pragma: no cover — exercised by tests via monkeypatch
    _HAS_ARGON2 = False
    _argon2_hash_raw = None
    _Argon2Type = None

try:
    import keyring as _keyring
    import keyring.errors as _keyring_errors
    _HAS_KEYRING = True
except Exception:  # pragma: no cover
    _HAS_KEYRING = False
    _keyring = None
    _keyring_errors = None

try:
    import win32crypt  # type: ignore
    _HAS_DPAPI = (platform.system() == "Windows")
except Exception:  # pragma: no cover
    _HAS_DPAPI = False
    win32crypt = None  # type: ignore


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

_VAULT_MAGIC = "NGSV"
_VAULT_VERSION = 1
_KEY_BYTES = 32         # AES-256 / Argon2id hash_len
_NONCE_BYTES = 12       # GCM standard
_SALT_BYTES = 16
_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")
_AUDIT_MAX = 5000

# Argon2id cost — defaults follow OWASP 2026 guidance for "interactive" KDFs.
# Tests override these with cheap values via env var to keep runtime sane.
_ARGON2_M_COST_DEFAULT = 65536   # 64 MiB
_ARGON2_T_COST_DEFAULT = 3
_ARGON2_PARALLELISM_DEFAULT = 4

_KEYRING_SERVICE = "NetGuardSecretVault"

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Exceptions — generic messages on purpose; never reveal name / blob size.
# --------------------------------------------------------------------------- #


class VaultError(Exception):
    """Base class for SecretVault errors."""


class VaultDependencyMissingError(VaultError):
    """A required Python package is not installed."""


class VaultBackendUnavailableError(VaultError):
    """A backend (keyring / DPAPI) is unreachable at runtime."""


class VaultNotInitializedError(VaultError):
    """Operation requires a vault that has been ``init()``-ed."""


class VaultAlreadyInitializedError(VaultError):
    """``init()`` called against an existing vault."""


class VaultLockedError(VaultError):
    """A mutating or reading call was made while locked."""


class VaultBadMasterError(VaultError):
    """Wrong master password (GCM tag mismatch on KEK_wrap)."""


class VaultCorruptedError(VaultError):
    """A ciphertext blob's GCM tag failed — file or memory tampered."""


# --------------------------------------------------------------------------- #
# Helpers — base64 / time / atomic write
# --------------------------------------------------------------------------- #


def _b64e(b: bytes) -> str:
    return base64.b64encode(bytes(b)).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _zeroize(buf: Any) -> None:
    """Best-effort zeroization of a bytearray. No-op on bytes / None."""
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write bytes via a temp file + ``os.replace`` for atomicity on NTFS."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass  # not all FSes support fsync
    os.replace(tmp, path)


def _caller_name(skip: int = 2) -> str:
    """Return the qualified module name of the public-API caller.

    Used for the audit log only; never logs argument values.
    """
    try:
        frame = sys._getframe(skip)
        mod = frame.f_globals.get("__name__", "?")
        func = frame.f_code.co_name
        return f"{mod}.{func}"
    except Exception:
        return "?"


# --------------------------------------------------------------------------- #
# DPAPI thin wrapper
# --------------------------------------------------------------------------- #


def _dpapi_protect(blob: bytes) -> Tuple[bytes, bool]:
    """Return (ciphertext, ok). On failure, returns (blob, False) — caller
    handles the degraded path by storing ``dek_dpapi_available=False``.
    """
    if not _HAS_DPAPI or win32crypt is None:
        return blob, False
    try:
        ct = win32crypt.CryptProtectData(
            bytes(blob), None, None, None, None, 0
        )
        return ct, True
    except Exception as exc:  # pragma: no cover
        logger.warning("DPAPI protect unavailable; degrading layer 1: %s",
                       type(exc).__name__)
        return blob, False


def _dpapi_unprotect(blob: bytes, was_dpapi_protected: bool) -> bytes:
    """Inverse of ``_dpapi_protect``. ``was_dpapi_protected=False`` means the
    blob is the raw inner value and DPAPI should not be invoked."""
    if not was_dpapi_protected:
        return bytes(blob)
    if not _HAS_DPAPI or win32crypt is None:
        # Cannot unprotect a DPAPI blob without DPAPI. Treat as backend failure
        # — caller surfaces as VaultBackendUnavailableError.
        raise VaultBackendUnavailableError(
            "vault DPAPI backend not available on this system"
        )
    try:
        _desc, pt = win32crypt.CryptUnprotectData(
            bytes(blob), None, None, None, 0
        )
        return bytes(pt)
    except Exception as exc:  # pragma: no cover
        # DPAPI failure on a blob that was DPAPI-protected = file tampered or
        # we are running as a different user. Either way, refuse to proceed.
        raise VaultCorruptedError(
            "vault outer envelope failed integrity check"
        ) from exc


# --------------------------------------------------------------------------- #
# Keyring thin wrapper — never logs the blind value
# --------------------------------------------------------------------------- #


def _keyring_get_blind(vault_id: str) -> Optional[bytes]:
    if not _HAS_KEYRING or _keyring is None:
        raise VaultDependencyMissingError(
            "Vault layer 2 requires the 'keyring' package: pip install keyring"
        )
    try:
        b64 = _keyring.get_password(_KEYRING_SERVICE, vault_id)
    except Exception as exc:
        raise VaultBackendUnavailableError(
            "vault keyring backend not reachable"
        ) from exc
    if not b64:
        return None
    try:
        b = _b64d(b64)
    except Exception:
        raise VaultCorruptedError("vault keyring entry malformed")
    if len(b) != _KEY_BYTES:
        raise VaultCorruptedError("vault keyring entry has wrong length")
    return b


def _keyring_set_blind(vault_id: str, blind: bytes) -> None:
    if not _HAS_KEYRING or _keyring is None:
        raise VaultDependencyMissingError(
            "Vault layer 2 requires the 'keyring' package: pip install keyring"
        )
    try:
        _keyring.set_password(_KEYRING_SERVICE, vault_id, _b64e(blind))
    except Exception as exc:
        raise VaultBackendUnavailableError(
            "vault keyring backend rejected write"
        ) from exc


def _keyring_delete_blind(vault_id: str) -> None:
    if not _HAS_KEYRING or _keyring is None:
        return
    try:
        _keyring.delete_password(_KEYRING_SERVICE, vault_id)
    except Exception:
        # Already deleted / no backend — non-fatal.
        pass


# --------------------------------------------------------------------------- #
# Argon2id thin wrapper
# --------------------------------------------------------------------------- #


def _argon2_params() -> Tuple[int, int, int]:
    """Read m_cost / t_cost / parallelism with env overrides for tests.

    Tests set SECRET_VAULT_ARGON2_FAST=1 to use cheap parameters
    (m=8, t=1, p=1) so a full suite stays under a few seconds.
    """
    if os.environ.get("SECRET_VAULT_ARGON2_FAST") == "1":
        return 8, 1, 1
    return (
        _ARGON2_M_COST_DEFAULT,
        _ARGON2_T_COST_DEFAULT,
        _ARGON2_PARALLELISM_DEFAULT,
    )


def _argon2_kdf(password: bytes, salt: bytes) -> bytes:
    if not _HAS_ARGON2 or _argon2_hash_raw is None:
        raise VaultDependencyMissingError(
            "Vault layer 3 requires 'argon2-cffi': pip install argon2-cffi"
        )
    m, t, p = _argon2_params()
    return _argon2_hash_raw(
        secret=bytes(password),
        salt=bytes(salt),
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=_KEY_BYTES,
        type=_Argon2Type.ID,
    )


# --------------------------------------------------------------------------- #
# AES-GCM helpers
# --------------------------------------------------------------------------- #


def _aead_seal(key: bytes, plaintext: bytes,
               aad: Optional[bytes] = None) -> bytes:
    nonce = _stdlib_secrets.token_bytes(_NONCE_BYTES)
    ct = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), aad)
    return nonce + ct


def _aead_open(key: bytes, blob: bytes,
               aad: Optional[bytes] = None) -> bytes:
    if len(blob) < _NONCE_BYTES + 16:  # 16 = GCM tag
        raise VaultCorruptedError("vault payload truncated")
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        # Tag failure is propagated as VaultBadMasterError or
        # VaultCorruptedError by the caller depending on context — the
        # caller knows whether it just tried to unwrap with user input.
        raise InvalidTag from exc


# --------------------------------------------------------------------------- #
# SecretVault
# --------------------------------------------------------------------------- #


class SecretVault:
    """Triple-encryption secrets store.

    See module docstring and ``docs/secret_vault_spec.md``.
    """

    def __init__(
        self,
        vault_root: Optional[Path] = None,
        idle_timeout_minutes: int = 15,
    ) -> None:
        self._lock = threading.RLock()
        self._idle_timeout = max(0, int(idle_timeout_minutes)) * 60
        self._last_activity: float = 0.0

        # In-RAM key material — only populated between unlock() and lock().
        self._dek: Optional[bytearray] = None
        self._vault_id: Optional[str] = None

        # Resolve storage path.
        if vault_root is not None:
            self._root = Path(vault_root) / ".secret_vault"
        else:
            override = os.environ.get("SECRET_VAULT_ROOT")
            if override:
                self._root = Path(override) / ".secret_vault"
            else:
                self._root = (
                    Path(__file__).resolve().parent
                    / "argus_data"
                    / ".secret_vault"
                )
        self._file = self._root / "secret_vault.bin"
        self._backup = self._root / "secret_vault.bin.bak"

    # ------------------------------------------------------------------ #
    # Public API — lifecycle
    # ------------------------------------------------------------------ #

    def exists(self) -> bool:
        """True iff a vault file is on disk."""
        return self._file.is_file()

    def init(self, master: str) -> None:
        """Create a new vault. Fails if one already exists."""
        with self._lock:
            self._touch()
            if self.exists():
                raise VaultAlreadyInitializedError(
                    "vault already initialized at this location"
                )
            self._require_layer_deps(strict_dpapi=False)

            master_b = bytearray(master.encode("utf-8"))
            try:
                vault_id = str(uuid.uuid4())
                salt_master = _stdlib_secrets.token_bytes(_SALT_BYTES)
                salt_keyring = _stdlib_secrets.token_bytes(_SALT_BYTES)

                kek_master = bytearray(_argon2_kdf(master_b, salt_master))
                kek_wrap = bytearray(_stdlib_secrets.token_bytes(_KEY_BYTES))
                blind = _stdlib_secrets.token_bytes(_KEY_BYTES)
                kek_unwrap = bytearray(
                    a ^ b for a, b in zip(kek_wrap, blind)
                )
                dek = bytearray(_stdlib_secrets.token_bytes(_KEY_BYTES))

                kek_wrap_blob = _aead_seal(
                    kek_master, bytes(kek_wrap),
                    aad=b"NGSV/kek_wrap"
                )
                dek_inner = _aead_seal(
                    kek_unwrap, bytes(dek),
                    aad=b"NGSV/dek"
                )
                dek_outer, dpapi_ok = _dpapi_protect(dek_inner)

                # Persist keyring blind FIRST so a crash mid-init can be
                # recovered by deleting the half-written file.
                _keyring_set_blind(vault_id, blind)

                doc = {
                    "magic": _VAULT_MAGIC,
                    "version": _VAULT_VERSION,
                    "vault_id": vault_id,
                    "created_at": _now_iso(),
                    "salt_master_b64": _b64e(salt_master),
                    "salt_keyring_b64": _b64e(salt_keyring),
                    "argon2_params": {
                        "type": "id",
                        "m_cost": _argon2_params()[0],
                        "t_cost": _argon2_params()[1],
                        "p": _argon2_params()[2],
                        "hash_len": _KEY_BYTES,
                    },
                    "kek_wrap_blob_b64": _b64e(kek_wrap_blob),
                    "dek_dpapi_blob_b64": _b64e(dek_outer),
                    "dek_dpapi_available": dpapi_ok,
                    "secrets": {},
                    "audit": [],
                }
                self._save_doc(doc)

                # Hold DEK so init() leaves the vault unlocked.
                self._dek = dek
                self._vault_id = vault_id
                self._append_audit(doc, "init", None, ok=True)
                self._save_doc(doc)
                self._touch()
            finally:
                _zeroize(master_b)
                # kek_master, kek_wrap, kek_unwrap are local — best-effort wipe.
                try:
                    _zeroize(kek_master)
                except Exception:
                    pass
                try:
                    _zeroize(kek_wrap)
                except Exception:
                    pass
                try:
                    _zeroize(kek_unwrap)
                except Exception:
                    pass

    def unlock(self, master: str) -> None:
        """Derive KEK_master, recover DEK, and hold it for the idle window."""
        with self._lock:
            if not self.exists():
                raise VaultNotInitializedError("vault not initialized")
            self._require_layer_deps(strict_dpapi=False)

            doc = self._load_doc()
            master_b = bytearray(master.encode("utf-8"))
            try:
                self._open_dek(doc, master_b)
                self._vault_id = doc["vault_id"]
                self._append_audit(doc, "unlock", None, ok=True)
                self._save_doc(doc)
                self._touch()
            finally:
                _zeroize(master_b)

    def lock(self) -> None:
        """Zeroize the in-memory DEK. Idempotent."""
        with self._lock:
            if self._dek is not None:
                _zeroize(self._dek)
                self._dek = None
            self._vault_id = None
            self._last_activity = 0.0

    def is_unlocked(self) -> bool:
        with self._lock:
            self._maybe_auto_lock()
            return self._dek is not None

    # ------------------------------------------------------------------ #
    # Public API — CRUD
    # ------------------------------------------------------------------ #

    def set(
        self,
        name: str,
        secret: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            self._require_unlocked()
            self._validate_name(name)

            doc = self._load_doc()
            secret_b = bytearray(secret.encode("utf-8"))
            try:
                ct = _aead_seal(
                    self._dek, bytes(secret_b),
                    aad=name.encode("utf-8"),
                )
                now = _now_iso()
                existing = doc["secrets"].get(name)
                doc["secrets"][name] = {
                    "ct_b64": _b64e(ct),
                    "created_at": existing["created_at"] if existing else now,
                    "updated_at": now,
                    "metadata": dict(metadata or {}),
                }
                self._append_audit(doc, "set", name, ok=True)
                self._save_doc(doc)
                self._touch()
            finally:
                _zeroize(secret_b)

    def get(self, name: str) -> Optional[str]:
        with self._lock:
            self._require_unlocked()
            self._validate_name(name)

            doc = self._load_doc()
            entry = doc["secrets"].get(name)
            if entry is None:
                self._append_audit(doc, "get", name, ok=False,
                                   error_class="NotFound")
                self._save_doc(doc)
                self._touch()
                return None
            try:
                pt = _aead_open(
                    self._dek, _b64d(entry["ct_b64"]),
                    aad=name.encode("utf-8"),
                )
            except InvalidTag:
                self._append_audit(doc, "get", name, ok=False,
                                   error_class="VaultCorruptedError")
                self._save_doc(doc)
                raise VaultCorruptedError(
                    "vault entry failed integrity check"
                )
            self._append_audit(doc, "get", name, ok=True)
            self._save_doc(doc)
            self._touch()
            try:
                return pt.decode("utf-8")
            finally:
                # pt is bytes (immutable) — cannot zero. The decoded str is
                # also immutable. This is the documented best-effort gap.
                del pt

    def list(self) -> List[Dict[str, Any]]:
        """Return per-secret metadata only — no plaintext, no ciphertext."""
        with self._lock:
            self._require_unlocked()
            doc = self._load_doc()
            out = []
            for name, entry in sorted(doc["secrets"].items()):
                out.append({
                    "name": name,
                    "created_at": entry.get("created_at"),
                    "updated_at": entry.get("updated_at"),
                    "metadata": dict(entry.get("metadata", {})),
                })
            self._append_audit(doc, "list", None, ok=True)
            self._save_doc(doc)
            self._touch()
            return out

    def delete(self, name: str) -> bool:
        with self._lock:
            self._require_unlocked()
            self._validate_name(name)
            doc = self._load_doc()
            had = name in doc["secrets"]
            if had:
                del doc["secrets"][name]
            self._append_audit(doc, "delete", name, ok=had)
            self._save_doc(doc)
            self._touch()
            return had

    # ------------------------------------------------------------------ #
    # Public API — change_master
    # ------------------------------------------------------------------ #

    def change_master(self, old: str, new: str) -> None:
        """Re-derive KEK_master with a new password; re-wrap KEK_wrap.

        Note: the on-disk DEK and per-secret ciphertexts are NOT re-encrypted —
        only the outermost wrap. This is sufficient because the master
        password is the *only* entry point to KEK_wrap; rotating it
        invalidates all attacker-known KEK_master values.

        If callers want to fully re-encrypt every secret (e.g. after
        suspected DEK compromise), call ``init()`` on a fresh location and
        copy via list/get/set.
        """
        with self._lock:
            if not self.exists():
                raise VaultNotInitializedError("vault not initialized")
            self._require_layer_deps(strict_dpapi=False)

            doc = self._load_doc()
            old_b = bytearray(old.encode("utf-8"))
            new_b = bytearray(new.encode("utf-8"))
            try:
                # Verify the old master by opening the DEK chain.
                self._open_dek(doc, old_b, retain_dek=False)

                # Derive new KEK_master with a *fresh* salt.
                new_salt = _stdlib_secrets.token_bytes(_SALT_BYTES)
                kek_master_new = bytearray(_argon2_kdf(new_b, new_salt))

                # Decrypt the existing KEK_wrap with the old key.
                old_salt = _b64d(doc["salt_master_b64"])
                kek_master_old = bytearray(_argon2_kdf(old_b, old_salt))
                try:
                    kek_wrap = bytearray(_aead_open(
                        kek_master_old,
                        _b64d(doc["kek_wrap_blob_b64"]),
                        aad=b"NGSV/kek_wrap",
                    ))
                except InvalidTag:
                    # Should not happen — _open_dek above succeeded with old.
                    raise VaultBadMasterError(
                        "vault rejected supplied credential"
                    )

                # Re-wrap under the new KEK_master.
                new_kek_wrap_blob = _aead_seal(
                    kek_master_new, bytes(kek_wrap),
                    aad=b"NGSV/kek_wrap",
                )
                doc["salt_master_b64"] = _b64e(new_salt)
                doc["kek_wrap_blob_b64"] = _b64e(new_kek_wrap_blob)

                self._append_audit(doc, "change_master", None, ok=True)
                self._save_doc(doc)
                self._touch()
            finally:
                _zeroize(old_b)
                _zeroize(new_b)
                try:
                    _zeroize(kek_master_old)  # type: ignore[name-defined]
                except Exception:
                    pass
                try:
                    _zeroize(kek_master_new)  # type: ignore[name-defined]
                except Exception:
                    pass
                try:
                    _zeroize(kek_wrap)  # type: ignore[name-defined]
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Public API — audit
    # ------------------------------------------------------------------ #

    def audit_log(self) -> List[Dict[str, Any]]:
        """Return a copy of the current audit log. Requires unlock."""
        with self._lock:
            self._require_unlocked()
            doc = self._load_doc()
            return list(doc.get("audit", []))

    # ------------------------------------------------------------------ #
    # Public API — migration
    # ------------------------------------------------------------------ #

    def migrate_from_settings_json(
        self,
        path: Path,
        master: str,
    ) -> int:
        """Move plaintext API keys out of ``netguard_ai_settings.json``.

        Idempotent: if the file already has ``api_key_in_vault: true`` for a
        provider, that provider is skipped.

        Returns the number of secrets migrated this call.
        """
        with self._lock:
            path = Path(path)
            if not path.is_file():
                return 0

            # Open the vault if not already.
            if not self.is_unlocked():
                if self.exists():
                    self.unlock(master)
                else:
                    self.init(master)

            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                # Malformed — refuse to overwrite.
                return 0

            providers = data.get("providers", {})
            if not isinstance(providers, dict):
                return 0

            placeholders = (
                "sk-ant-REPLACE-ME",
                "sk-REPLACE-ME",
                "AIza-REPLACE-ME",
                "",
            )
            migrated = 0
            for prov_name, prov_cfg in providers.items():
                if not isinstance(prov_cfg, dict):
                    continue
                key = prov_cfg.get("api_key", "")
                if prov_cfg.get("api_key_in_vault") is True and not key:
                    continue
                if not isinstance(key, str) or key in placeholders:
                    continue

                vault_name = f"{prov_name}_api_key"
                self.set(
                    vault_name, key,
                    metadata={"provider": prov_name, "migrated_from": str(path)},
                )
                prov_cfg.pop("api_key", None)
                prov_cfg["api_key_in_vault"] = True
                migrated += 1

            if migrated > 0:
                # Backup original then rewrite.
                backup = path.with_suffix(path.suffix + ".pre-vault.bak")
                if not backup.exists():
                    backup.write_bytes(path.read_bytes())
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                    f.write("\n")
            return migrated

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _require_layer_deps(self, strict_dpapi: bool) -> None:
        if not _HAS_ARGON2:
            raise VaultDependencyMissingError(
                "Vault layer 3 requires 'argon2-cffi': pip install argon2-cffi"
            )
        if not _HAS_KEYRING:
            raise VaultDependencyMissingError(
                "Vault layer 2 requires 'keyring': pip install keyring"
            )
        if strict_dpapi and not _HAS_DPAPI:
            raise VaultDependencyMissingError(
                "Vault layer 1 requires 'pywin32' on Windows: pip install pywin32"
            )

    def _require_unlocked(self) -> None:
        self._maybe_auto_lock()
        if self._dek is None:
            raise VaultLockedError("vault is locked")

    def _validate_name(self, name: str) -> None:
        if not isinstance(name, str) or not _NAME_RE.match(name):
            # Generic message — never echoes the bad name.
            raise VaultError("invalid secret name")

    def _maybe_auto_lock(self) -> None:
        if self._idle_timeout <= 0:
            return
        if self._dek is None:
            return
        if self._last_activity <= 0.0:
            return
        if (time.monotonic() - self._last_activity) > self._idle_timeout:
            self.lock()

    def _touch(self) -> None:
        self._last_activity = time.monotonic()

    def _open_dek(
        self,
        doc: Dict[str, Any],
        master_b: bytearray,
        retain_dek: bool = True,
    ) -> None:
        """Walk Layer 3 → Layer 2 → Layer 1 to recover the DEK.

        If ``retain_dek`` is True, the DEK is stored on ``self._dek``.
        """
        # Validate header
        if (
            doc.get("magic") != _VAULT_MAGIC
            or doc.get("version") != _VAULT_VERSION
        ):
            raise VaultCorruptedError("vault header invalid")

        # Layer 3 — Argon2id
        salt_master = _b64d(doc["salt_master_b64"])
        kek_master = bytearray(_argon2_kdf(master_b, salt_master))
        try:
            try:
                kek_wrap = bytearray(_aead_open(
                    kek_master,
                    _b64d(doc["kek_wrap_blob_b64"]),
                    aad=b"NGSV/kek_wrap",
                ))
            except InvalidTag:
                raise VaultBadMasterError(
                    "vault rejected supplied credential"
                )

            # Layer 2 — Keyring blind
            blind = _keyring_get_blind(doc["vault_id"])
            if blind is None:
                raise VaultBackendUnavailableError(
                    "vault keyring entry missing for this machine"
                )
            kek_unwrap = bytearray(a ^ b for a, b in zip(kek_wrap, blind))

            # Layer 1 — DPAPI outer envelope
            dek_outer = _b64d(doc["dek_dpapi_blob_b64"])
            dek_inner = _dpapi_unprotect(
                dek_outer, doc.get("dek_dpapi_available", False)
            )

            # Inner GCM unwrap
            try:
                dek = bytearray(_aead_open(
                    kek_unwrap, dek_inner, aad=b"NGSV/dek"
                ))
            except InvalidTag:
                raise VaultCorruptedError(
                    "vault inner envelope failed integrity check"
                )

            if retain_dek:
                # Replace any prior DEK.
                if self._dek is not None:
                    _zeroize(self._dek)
                self._dek = dek
            else:
                _zeroize(dek)
        finally:
            _zeroize(kek_master)
            try:
                _zeroize(kek_wrap)  # type: ignore[name-defined]
            except Exception:
                pass
            try:
                _zeroize(kek_unwrap)  # type: ignore[name-defined]
            except Exception:
                pass

    def _append_audit(
        self,
        doc: Dict[str, Any],
        op: str,
        name: Optional[str],
        ok: bool,
        error_class: Optional[str] = None,
    ) -> None:
        entry = {
            "ts": _now_iso(),
            "op": op,
            "name": name,
            "caller": _caller_name(skip=3),
            "ok": ok,
            "error_class": error_class,
        }
        log = doc.setdefault("audit", [])
        log.append(entry)
        if len(log) > _AUDIT_MAX:
            # Drop oldest in bulk to amortize cost.
            del log[: len(log) - _AUDIT_MAX]

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def _load_doc(self) -> Dict[str, Any]:
        if not self._file.is_file():
            raise VaultNotInitializedError("vault not initialized")
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception:
            raise VaultCorruptedError("vault file unreadable")
        if not isinstance(doc, dict):
            raise VaultCorruptedError("vault file shape invalid")
        return doc

    def _save_doc(self, doc: Dict[str, Any]) -> None:
        # Backup the previous good file first.
        if self._file.is_file():
            try:
                self._backup.parent.mkdir(parents=True, exist_ok=True)
                self._backup.write_bytes(self._file.read_bytes())
            except Exception:
                # Backup is best-effort.
                pass
        payload = json.dumps(
            doc, indent=2, ensure_ascii=False
        ).encode("utf-8")
        _atomic_write_bytes(self._file, payload)

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #

    def destroy(self) -> None:
        """DELETE the vault file AND the keyring entry. Irreversible.

        Intended for tests and explicit user "wipe" actions only. Does NOT
        require unlock — anyone with file access can wipe their own vault.
        """
        with self._lock:
            self.lock()
            if self.exists():
                try:
                    doc = self._load_doc()
                    vid = doc.get("vault_id")
                except Exception:
                    vid = None
                try:
                    self._file.unlink()
                except Exception:
                    pass
                try:
                    if self._backup.is_file():
                        self._backup.unlink()
                except Exception:
                    pass
                if vid:
                    _keyring_delete_blind(vid)


# --------------------------------------------------------------------------- #
# Module-level convenience: a default singleton (lazy)
# --------------------------------------------------------------------------- #


_default_vault: Optional[SecretVault] = None
_default_lock = threading.Lock()


def get_default_vault() -> SecretVault:
    """Return the process-wide default vault.

    Useful for callers that don't want to manage their own ``SecretVault``
    instance. Storage path follows ``SECRET_VAULT_ROOT`` or the production
    default.
    """
    global _default_vault
    with _default_lock:
        if _default_vault is None:
            _default_vault = SecretVault()
        return _default_vault


__all__ = [
    "SecretVault",
    "VaultError",
    "VaultDependencyMissingError",
    "VaultBackendUnavailableError",
    "VaultNotInitializedError",
    "VaultAlreadyInitializedError",
    "VaultLockedError",
    "VaultBadMasterError",
    "VaultCorruptedError",
    "get_default_vault",
]
