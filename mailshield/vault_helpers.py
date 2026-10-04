# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Secret-vault hookups for MailShield Pro.

MailShield's secrets are per-account: the ``mailshield_settings.json``
file stores a list of account dicts, each with its own IMAP/SMTP
password, username, and (optionally) a refresh token. A single global
vault key is therefore not sufficient — we namespace by account email.

Vault key naming convention:

    mailshield.account.<email_lower>.password
    mailshield.account.<email_lower>.refresh_token
    mailshield.account.<email_lower>.access_token   (low-priority,
                                                     rotates often)
    mailshield.imap.password   (back-compat; first account only)
    mailshield.smtp.password   (back-compat; first account only)
    mailshield.anthropic.api_key
    mailshield.openai.api_key

The legacy XOR-based ``PasswordVault`` in ``mailshield.py`` is kept as
a fallback so existing settings files keep working when the suite-wide
``SecretVault`` is locked or unavailable. Reads always check the
SecretVault first; a non-empty value wins. Writes go BOTH to the vault
(when unlocked) and to the legacy XOR field (so the file remains usable
if a future user rolls back).
"""

from __future__ import annotations

import json
import logging
import re
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("MailShield.Vault")


# Normalize an email for use as a vault-key suffix. We want to be lenient
# on the input (mixed case, leading/trailing whitespace) and strict on
# the output (only chars that match the SecretVault name regex,
# ``^[A-Za-z0-9_.\-]{1,128}$``).
_EMAIL_TO_KEY_RE = re.compile(r"[^A-Za-z0-9_.\-]")


def _email_to_key_suffix(email: str) -> str:
    """Turn ``Foo.Bar+work@Example.com`` into ``foo.bar_work_example.com``."""
    if not email:
        return ""
    safe = _EMAIL_TO_KEY_RE.sub("_", email.strip().lower())
    # Trim to leave room for the prefix (max 128 chars total).
    return safe[:96]


def account_password_key(email: str) -> str:
    """Return the vault key for an account's IMAP/SMTP password."""
    suffix = _email_to_key_suffix(email)
    return f"mailshield.account.{suffix}.password" if suffix else ""


def account_refresh_token_key(email: str) -> str:
    """Return the vault key for an OAuth2 refresh token."""
    suffix = _email_to_key_suffix(email)
    return f"mailshield.account.{suffix}.refresh_token" if suffix else ""


# Top-level (non-per-account) vault keys we know about.
MAILSHIELD_GLOBAL_VAULT_KEYS: Dict[str, str] = {
    "anthropic_api_key": "mailshield.anthropic.api_key",
    "openai_api_key":    "mailshield.openai.api_key",
}


# --- lazy singleton ---------------------------------------------------------

_VAULT: Any = None  # None | False | SecretVault instance
_VAULT_LOCK = threading.Lock()
_VAULT_LOCKED_WARNED = False


def get_vault() -> Optional[Any]:
    """Return the process-wide SecretVault instance, or ``None`` if the
    vault is unavailable. Failures are cached so we never thrash."""
    global _VAULT
    if _VAULT is not None:
        return _VAULT if _VAULT is not False else None
    with _VAULT_LOCK:
        if _VAULT is None:
            try:
                from secret_vault import SecretVault  # type: ignore
                _VAULT = SecretVault()
            except Exception as e:  # pragma: no cover - defensive
                try:
                    logger.warning(
                        "[MailShield.Vault] unavailable: %s — using plaintext fallback",
                        type(e).__name__,
                    )
                except Exception:
                    pass
                _VAULT = False
    return _VAULT if _VAULT is not False else None


def vault_initialized() -> bool:
    v = get_vault()
    if v is None:
        return False
    try:
        return bool(v.exists())
    except Exception:
        return False


def vault_unlocked() -> bool:
    v = get_vault()
    if v is None:
        return False
    try:
        return bool(v.exists()) and bool(v.is_unlocked())
    except Exception:
        return False


def get_secret(name: str, fallback: Optional[str] = None) -> Optional[str]:
    """Lookup a secret. Same semantics as ``netguard.get_secret`` —
    vault-when-unlocked, else fallback. Empty vault values fall through
    to the fallback so existing ``if not value`` guards keep working."""
    global _VAULT_LOCKED_WARNED
    if not name:
        return fallback or None
    v = get_vault()
    if v is not None:
        try:
            if v.exists():
                if v.is_unlocked():
                    val = v.get(name)
                    if val:
                        return val
                else:
                    if not _VAULT_LOCKED_WARNED:
                        try:
                            logger.warning(
                                "[MailShield.Vault] locked — secret '%s' not retrievable until unlock",
                                name,
                            )
                        except Exception:
                            pass
                        _VAULT_LOCKED_WARNED = True
                    return None
        except Exception as e:  # pragma: no cover - defensive
            try:
                logger.debug("[MailShield.Vault] get(%s) failed: %s", name, type(e).__name__)
            except Exception:
                pass
    return fallback or None


def set_secret(name: str, value: str) -> bool:
    """Write a secret. Returns True on success; never raises."""
    if not name:
        return False
    v = get_vault()
    if v is None:
        return False
    try:
        if not v.exists() or not v.is_unlocked():
            return False
        v.set(name, value)
        return True
    except Exception as e:  # pragma: no cover - defensive
        try:
            logger.debug("[MailShield.Vault] set(%s) failed: %s", name, type(e).__name__)
        except Exception:
            pass
        return False


# --- migration --------------------------------------------------------------


def _looks_like_xor_envelope(value: str) -> bool:
    """Did MailShield's legacy XOR PasswordVault wrap this value?

    XOR-encrypted passwords get an ``ENC:`` prefix in mailshield.py.
    We need to know because (a) the vault stores the *plaintext*, not
    the XOR envelope, and (b) we cannot decrypt without the legacy
    PasswordVault — so the migration helper takes a decrypt callback.
    """
    return isinstance(value, str) and value.startswith("ENC:")


def migrate_to_vault(
    settings: Dict[str, Any],
    decrypt_password: Optional[Callable[[str], str]] = None,
    settings_path: Optional[Path] = None,
    save_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Tuple[List[str], int]:
    """Move every plaintext / XOR-wrapped secret in ``settings`` into the
    suite-wide :class:`SecretVault`.

    Args:
      settings: the in-memory MailShield settings dict (mutated in place).
      decrypt_password: callable that takes a stored password (which
        may be XOR-wrapped via the legacy ``PasswordVault``) and returns
        the plaintext. When omitted, XOR-wrapped values are skipped —
        we never store the XOR envelope as a "vault secret".
      settings_path: when provided, the helper writes a
        ``<path>.pre-vault.bak`` once and then rewrites the cleaned
        settings as JSON. When ``save_callback`` is provided, that
        callback is invoked instead.
      save_callback: alternative to ``settings_path`` — typically
        ``mailshield.save_settings``, which already handles the
        XOR-encryption-on-save dance.

    Returns ``(migrated_keys, count)``. Migrated entries follow the
    convention ``account:<email>:password`` for accounts and the global
    key for top-level secrets. ``count == 0`` is normal.
    """
    v = get_vault()
    if v is None:
        return [], 0
    try:
        if not v.exists() or not v.is_unlocked():
            return [], 0
    except Exception:
        return [], 0

    migrated: List[str] = []

    # 1. Per-account passwords.
    accounts = settings.get("accounts") or []
    if isinstance(accounts, list):
        for acc in accounts:
            if not isinstance(acc, dict):
                continue
            email = (acc.get("email") or "").strip()
            stored = acc.get("password") or ""
            if not email or not isinstance(stored, str) or not stored:
                continue
            # Decrypt XOR envelopes when the caller provided a decryptor.
            if _looks_like_xor_envelope(stored):
                if decrypt_password is None:
                    continue  # we never put ENC: blobs in the vault
                try:
                    plaintext = decrypt_password(stored)
                except Exception:
                    continue
                if not plaintext:
                    continue
            else:
                plaintext = stored
            key = account_password_key(email)
            if not key:
                continue
            try:
                v.set(key, plaintext)
            except Exception as e:  # pragma: no cover
                try:
                    logger.warning(
                        "[MailShield.Vault] migrate account password failed: %s",
                        type(e).__name__,
                    )
                except Exception:
                    pass
                continue
            # Strip plaintext / XOR envelope from settings.
            acc["password"] = ""
            acc["password_in_vault"] = True
            migrated.append(f"account:{email.lower()}:password")

            # OAuth refresh tokens, if stashed in the account.
            refresh = acc.get("refresh_token") or ""
            if isinstance(refresh, str) and refresh:
                try:
                    v.set(account_refresh_token_key(email), refresh)
                    acc["refresh_token"] = ""
                    acc["refresh_token_in_vault"] = True
                    migrated.append(f"account:{email.lower()}:refresh_token")
                except Exception as e:  # pragma: no cover
                    try:
                        logger.warning(
                            "[MailShield.Vault] migrate refresh_token failed: %s",
                            type(e).__name__,
                        )
                    except Exception:
                        pass

    # 2. Top-level (non-per-account) secrets.
    for cfg_key, vault_name in MAILSHIELD_GLOBAL_VAULT_KEYS.items():
        val = settings.get(cfg_key)
        if not isinstance(val, str) or not val.strip():
            continue
        try:
            v.set(vault_name, val.strip())
            settings[cfg_key] = ""
            migrated.append(cfg_key)
        except Exception as e:  # pragma: no cover
            try:
                logger.warning(
                    "[MailShield.Vault] migrate %s failed: %s",
                    cfg_key,
                    type(e).__name__,
                )
            except Exception:
                pass

    # 3. Persist the cleaned settings.
    if migrated:
        if save_callback is not None:
            try:
                save_callback(settings)
            except Exception as e:  # pragma: no cover
                try:
                    logger.warning(
                        "[MailShield.Vault] save_callback failed: %s",
                        type(e).__name__,
                    )
                except Exception:
                    pass
        elif settings_path is not None:
            try:
                p = Path(settings_path)
                if p.is_file():
                    backup = p.with_suffix(p.suffix + ".pre-vault.bak")
                    if not backup.exists():
                        backup.write_bytes(p.read_bytes())
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(settings, f, indent=4, ensure_ascii=False)
                    f.write("\n")
            except Exception as e:  # pragma: no cover
                try:
                    logger.warning(
                        "[MailShield.Vault] settings rewrite failed: %s",
                        type(e).__name__,
                    )
                except Exception:
                    pass

    return migrated, len(migrated)


def reset_vault_singleton_for_tests() -> None:
    """Test-only helper. Clears the cached vault and warning flag."""
    global _VAULT, _VAULT_LOCKED_WARNED
    _VAULT = None
    _VAULT_LOCKED_WARNED = False
