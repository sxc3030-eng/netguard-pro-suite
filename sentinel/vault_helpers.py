# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Secret-vault hookups for SentinelOS.

This module gives the Sentinel package its own lazy ``SecretVault``
singleton + ``get_secret(name, fallback)`` helper, mirroring the pattern
used in ``netguard.py`` and ``argus_ai_providers.py``.

Behaviour summary
-----------------
* The first call to :func:`get_vault` constructs a ``SecretVault`` with
  the suite-wide default storage location. Construction is cheap (no I/O,
  no key derivation) so a missing-deps build only logs a warning.
* :func:`get_secret` is the single read entry point used by Sentinel
  modules (``alert_manager.py``, ``cortex.py``). It returns the vault
  value when the vault is initialized AND unlocked; otherwise it returns
  the supplied fallback (typically the value plucked from a settings
  dict). Empty-string vault values fall through to the fallback so that
  callers' existing ``if not value`` guards keep working.
* :func:`migrate_to_vault` moves the well-known plaintext secrets out of
  ``sentinel_settings.json`` (or any settings dict) into the vault and
  rewrites the settings file with a ``.pre-vault.bak`` backup. It is
  idempotent: secrets already moved are skipped.
* All entry points degrade gracefully — a vault failure NEVER raises out
  of these helpers; callers see ``None`` / their fallback and continue.

Vault key naming convention (also documented in the docstring of
:data:`SENTINEL_VAULT_KEYS`):

  * ``sentinel.smtp.password``     — outbound SMTP password
  * ``sentinel.smtp.user``         — outbound SMTP username (when stored)
  * ``sentinel.slack.webhook``     — Slack incoming webhook URL
  * ``sentinel.discord.webhook``   — Discord incoming webhook URL
  * ``sentinel.teams.webhook``     — Microsoft Teams incoming webhook URL
  * ``sentinel.telegram.bot_token``— Telegram Bot API token
  * ``sentinel.telegram.chat_id``  — Telegram chat ID (low sensitivity but
                                     paired with the bot token in practice)
  * ``sentinel.nvd.api_token``     — NVD CVE feed API token
  * ``sentinel.github.token``      — GitHub Security Advisories token
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("SentinelOS.Vault")


# Mapping from settings.json key -> vault secret name.
# Used by :func:`migrate_to_vault` and exposed for documentation /
# test introspection. Order is preserved for deterministic migration.
SENTINEL_VAULT_KEYS: Dict[str, str] = {
    "telegram_bot_token":     "sentinel.telegram.bot_token",
    "telegram_chat_id":       "sentinel.telegram.chat_id",
    "discord_webhook_url":    "sentinel.discord.webhook",
    "slack_webhook_url":      "sentinel.slack.webhook",
    "teams_webhook_url":      "sentinel.teams.webhook",
    "smtp_password":          "sentinel.smtp.password",
    "smtp_user":              "sentinel.smtp.user",
    "nvd_api_token":          "sentinel.nvd.api_token",
    "github_token":           "sentinel.github.token",
}


# --- lazy singleton ---------------------------------------------------------

_VAULT: Any = None  # None | False | SecretVault instance
_VAULT_LOCK = threading.Lock()
_VAULT_LOCKED_WARNED = False


def get_vault() -> Optional[Any]:
    """Return the process-wide SecretVault instance, or ``None`` if the
    vault is unavailable for any reason.

    The first call constructs the vault inside a lock; subsequent calls
    return the cached value. Failures are cached as the sentinel
    ``False`` so we do not retry on every ``get_secret`` call.
    """
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
                        "[Sentinel.Vault] unavailable: %s — using plaintext fallback",
                        type(e).__name__,
                    )
                except Exception:
                    pass
                _VAULT = False
    return _VAULT if _VAULT is not False else None


def vault_initialized() -> bool:
    """``True`` iff a vault file exists on disk for this user."""
    v = get_vault()
    if v is None:
        return False
    try:
        return bool(v.exists())
    except Exception:
        return False


def vault_unlocked() -> bool:
    """``True`` iff a vault is initialized AND currently unlocked."""
    v = get_vault()
    if v is None:
        return False
    try:
        return bool(v.exists()) and bool(v.is_unlocked())
    except Exception:
        return False


def get_secret(name: str, fallback: Optional[str] = None) -> Optional[str]:
    """Lookup a secret by its vault name.

    Lookup order:
      1. If the vault exists AND is unlocked, return its stored value
         (skipping empty strings — those fall through to the fallback so
         existing ``if not key`` guards keep working).
      2. If the vault exists but is locked, return ``None`` and emit a
         single warning the first time it happens.
      3. Otherwise return ``fallback`` unchanged. ``None``/empty fallback
         maps to ``None`` for caller convenience.
    """
    global _VAULT_LOCKED_WARNED
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
                                "[Sentinel.Vault] locked — secret '%s' not retrievable until unlock",
                                name,
                            )
                        except Exception:
                            pass
                        _VAULT_LOCKED_WARNED = True
                    return None
        except Exception as e:  # pragma: no cover - defensive
            try:
                logger.debug("[Sentinel.Vault] get(%s) failed: %s", name, type(e).__name__)
            except Exception:
                pass
    return fallback or None


def set_secret(name: str, value: str) -> bool:
    """Write a secret. Returns ``True`` on success, ``False`` if the
    vault is unavailable or locked. Never raises."""
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
            logger.debug("[Sentinel.Vault] set(%s) failed: %s", name, type(e).__name__)
        except Exception:
            pass
        return False


# --- migration --------------------------------------------------------------


def _is_secret_value(value: Any) -> bool:
    """A non-empty string is the only thing we migrate. ``None``/``""``
    means the user never configured this secret, so skip it."""
    return isinstance(value, str) and bool(value.strip())


def migrate_to_vault(
    settings: Dict[str, Any],
    settings_path: Optional[Path] = None,
    save_callback: Any = None,
) -> Tuple[List[str], int]:
    """Move every plaintext secret found in ``settings`` into the vault.

    Caller is responsible for ensuring the vault is unlocked beforehand
    (typically through :data:`netguard.vault_migrate` which already
    handles the master-password dance for the whole suite).

    The function:
      1. Iterates :data:`SENTINEL_VAULT_KEYS` in order.
      2. For each settings key holding a non-empty plaintext, writes the
         value to the vault under the namespaced name and clears it from
         ``settings``.
      3. If at least one secret moved AND ``settings_path`` is provided,
         writes ``<settings_path>.pre-vault.bak`` (only if a backup does
         not already exist) and persists the cleaned ``settings`` back to
         ``settings_path`` as JSON.
      4. If ``save_callback`` is supplied, calls it with no arguments
         instead of doing the file write — useful for callers that share
         a single in-memory ``SETTINGS`` dict and have their own save
         path.

    Returns ``(migrated_keys, count)``. ``count == 0`` is a perfectly
    valid result (nothing to migrate) and does NOT raise.
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
    for cfg_key, vault_name in SENTINEL_VAULT_KEYS.items():
        val = settings.get(cfg_key)
        if not _is_secret_value(val):
            continue
        try:
            v.set(vault_name, val.strip())
        except Exception as e:  # pragma: no cover - defensive
            try:
                logger.warning(
                    "[Sentinel.Vault] migrate %s failed: %s",
                    cfg_key,
                    type(e).__name__,
                )
            except Exception:
                pass
            continue
        # Strip plaintext from the in-memory settings dict.
        settings[cfg_key] = ""
        migrated.append(cfg_key)

    if migrated:
        if save_callback is not None:
            try:
                save_callback()
            except Exception as e:  # pragma: no cover
                try:
                    logger.warning("[Sentinel.Vault] save_callback failed: %s",
                                   type(e).__name__)
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
                    json.dump(settings, f, indent=2, ensure_ascii=False)
                    f.write("\n")
            except Exception as e:  # pragma: no cover
                try:
                    logger.warning(
                        "[Sentinel.Vault] settings rewrite failed: %s",
                        type(e).__name__,
                    )
                except Exception:
                    pass

    return migrated, len(migrated)


def reset_vault_singleton_for_tests() -> None:
    """Test-only helper: clear the cached vault so subsequent calls
    re-resolve. Production code MUST NOT call this."""
    global _VAULT, _VAULT_LOCKED_WARNED
    _VAULT = None
    _VAULT_LOCKED_WARNED = False
