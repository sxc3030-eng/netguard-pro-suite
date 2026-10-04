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
Unified secrets resolver for the NetGuard / Argus suite.

Resolution order (first hit wins):
    1. Argus Vault          (encrypted, AES-256-GCM + DPAPI / PBKDF2)
    2. ``.env`` file        (loaded once at module import via python-dotenv)
    3. ``os.environ``       (process / OS environment variables)
    4. Caller-supplied fallback

The vault is the recommended path for production use because keys never
hit disk in plaintext. ``.env`` is offered for developer convenience and
is gitignored at the repo root. ``os.environ`` exists so Docker / CI
secrets keep working without code changes.

Public API (module-level — no class needed):
    get_secret(name, fallback=None)       -> Optional[str]
    get_required_secret(name, hint="")    -> str    (raises if missing)
    list_known_secrets()                  -> list[str]
    store_secret(name, value, owner)      -> None   (auto-inits vault)

CANONICAL_SECRETS lists every secret the suite is *aware of*. UIs (the
first-run wizard, Settings → API Keys panel) iterate over this dict to
present a consistent list. Adding a new secret is a one-line edit here.
"""

from __future__ import annotations

import os
from typing import Optional

# python-dotenv is BSD-3-Clause licensed (GPL-compatible). Optional dep:
# if it isn't installed we silently skip .env loading rather than crash.
try:
    from dotenv import load_dotenv as _load_dotenv

    # Loads ``.env`` from the current working directory or any parent.
    # ``override=False`` means real OS env vars win over .env values
    # — that's what production users expect when they ssh in.
    _load_dotenv(override=False)
except Exception:  # pragma: no cover - dotenv is best-effort
    pass

# Vault is also optional at import time: if the cryptography wheel is
# missing in some weird minimal install we don't want to break the whole
# config layer. The functions below check ``_VAULT_OK`` before calling.
try:
    from argus_vault import (  # type: ignore[import-not-found]
        VaultError,
        vault_exists,
        vault_get,
        vault_init,
        vault_set,
    )

    _VAULT_OK = True
except Exception:  # pragma: no cover - vault is best-effort
    _VAULT_OK = False


# --------------------------------------------------------------------------- #
# Canonical secret catalogue
# --------------------------------------------------------------------------- #

# Mapping of secret name -> human-readable description.
# Order matters: it's the order the wizard displays them in.
CANONICAL_SECRETS: dict[str, str] = {
    # === AI Providers ===
    "ANTHROPIC_API_KEY": "Anthropic Claude API key (console.anthropic.com)",
    "OPENAI_API_KEY":    "OpenAI ChatGPT API key (platform.openai.com)",
    "GOOGLE_API_KEY":    "Google Gemini API key (aistudio.google.com)",
    "OLLAMA_BASE_URL":   "Local Ollama server URL (default http://localhost:11434)",
    # === Threat Intelligence ===
    "VIRUSTOTAL_API_KEY":  "VirusTotal API key (virustotal.com)",
    "ABUSEIPDB_API_KEY":   "AbuseIPDB API key (abuseipdb.com)",
    "MAXMIND_LICENSE_KEY": "MaxMind GeoIP license key (maxmind.com)",
    "MAXMIND_ACCOUNT_ID":  "MaxMind account ID (paired with license key)",
    # === Notifications ===
    "DISCORD_WEBHOOK_URL": "Discord webhook URL for alerts",
    "TELEGRAM_BOT_TOKEN":  "Telegram bot token (BotFather)",
    "TELEGRAM_CHAT_ID":    "Telegram chat ID for alert delivery",
}


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def get_secret(name: str, fallback: Optional[str] = None) -> Optional[str]:
    """Resolve a secret. Order: vault -> .env / OS env -> fallback.

    ``.env`` values are already merged into ``os.environ`` at import time,
    so a single ``os.environ.get`` covers both layers.

    Empty strings are treated as missing — many users leave a blank line
    in ``.env`` (``KEY=``) when they don't have a value yet, and we don't
    want that to silently shadow the vault entry.

    Returns ``None`` if not found and no fallback is supplied.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("secret name must be a non-empty string")

    # 1. Vault — most secure, checked first.
    if _VAULT_OK and vault_exists():
        try:
            value = vault_get(name)
            if value:
                return value
        except VaultError:
            # Vault corrupt or locked — degrade gracefully to env vars.
            pass

    # 2 & 3. .env (already loaded into os.environ) and OS env vars.
    env_val = os.environ.get(name)
    if env_val:
        return env_val

    return fallback


def get_required_secret(name: str, hint: str = "") -> str:
    """Same as ``get_secret`` but raise ``RuntimeError`` if missing.

    The error message lists the three supported ways to provide a secret
    so users can self-serve without grep-ing the source.
    """
    value = get_secret(name)
    if value:
        return value

    description = CANONICAL_SECRETS.get(name, "")
    detail = f" ({description})" if description else ""
    extra = f"\nHint: {hint}" if hint else ""
    raise RuntimeError(
        f"Required secret {name!r}{detail} is not set.\n"
        f"Provide it one of three ways:\n"
        f"  1. Settings -> API Keys (recommended; stores in encrypted vault)\n"
        f"  2. Add  {name}=...  to a .env file at the repo root\n"
        f"  3. Export {name} in your OS environment before launching"
        f"{extra}"
    )


def list_known_secrets() -> list[str]:
    """Return the canonical list of secret names this suite uses.

    UIs (first-run wizard, Settings panel) iterate this to render a
    consistent input list. The order matches ``CANONICAL_SECRETS``.
    """
    return list(CANONICAL_SECRETS.keys())


def store_secret(name: str, value: str, owner: str = "user") -> None:
    """Persist a secret in the encrypted vault.

    Auto-initialises the vault on first use. On Windows this happens
    silently via DPAPI (no passphrase required). On non-Windows hosts
    this raises ``VaultPassphraseRequiredError`` — those users must
    call ``vault_init(passphrase=...)`` themselves first.
    """
    if not _VAULT_OK:
        raise RuntimeError(
            "argus_vault module is not available; "
            "cannot store secrets in the encrypted vault"
        )
    if not isinstance(name, str) or not name:
        raise ValueError("secret name must be a non-empty string")
    if not isinstance(value, str):
        raise ValueError("secret value must be a string")

    if not vault_exists():
        # On Windows this succeeds silently via DPAPI. Elsewhere it
        # raises VaultPassphraseRequiredError, which we let bubble up.
        vault_init()

    vault_set(name, value, owner=owner)
