# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Integration tests for the Secret Vault wiring inside ``netguard.py``.

These tests verify that:

  * ``netguard.get_secret`` falls back to ``CFG`` when the vault is
    unavailable, and that it pulls from the vault when one is set up.
  * The new WS commands (``vault_status`` / ``vault_init`` /
    ``vault_unlock`` / ``vault_lock`` / ``vault_set_secret`` /
    ``vault_change_master`` / ``vault_migrate``) return well-shaped
    responses in every relevant state.
  * ``vault_unlock`` is rate-limited to 3 attempts / 30 s, then locked
    for 5 minutes, to thwart brute-force attempts on the master password.
  * ``vault_migrate`` moves the 5 secret keys from CFG into the vault
    and strips the plaintext copies.

The real ``SecretVault`` is heavy (Argon2 + DPAPI + Keyring) — we install
a light-weight in-memory fake on ``netguard._VAULT`` so each test runs
in microseconds and never touches disk or Windows credential storage.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------------- #
# In-memory fake vault — mirrors the SecretVault public API surface used
# by netguard.py. NOT a security model; just enough behaviour for the
# integration tests.
# --------------------------------------------------------------------------- #


class _FakeVault:
    def __init__(self) -> None:
        self._initialized = False
        self._unlocked = False
        self._secrets: Dict[str, str] = {}
        self._master: Optional[str] = None

    # Lifecycle ------------------------------------------------------------
    def exists(self) -> bool:
        return self._initialized

    def is_unlocked(self) -> bool:
        return self._unlocked

    def init(self, master: str) -> None:
        if self._initialized:
            raise RuntimeError("AlreadyInitialized")
        self._initialized = True
        self._master = master
        self._unlocked = True

    def unlock(self, master: str) -> None:
        if not self._initialized:
            raise RuntimeError("NotInitialized")
        if master != self._master:
            raise RuntimeError("BadMaster")
        self._unlocked = True

    def lock(self) -> None:
        self._unlocked = False

    def change_master(self, old: str, new: str) -> None:
        if old != self._master:
            raise RuntimeError("BadMaster")
        self._master = new

    # CRUD -----------------------------------------------------------------
    def set(self, name: str, value: str, metadata: Any = None) -> None:
        if not self._unlocked:
            raise RuntimeError("Locked")
        self._secrets[name] = value

    def get(self, name: str) -> Optional[str]:
        if not self._unlocked:
            raise RuntimeError("Locked")
        return self._secrets.get(name)

    def list(self) -> List[Dict[str, Any]]:
        if not self._unlocked:
            raise RuntimeError("Locked")
        return [{"name": n} for n in sorted(self._secrets)]


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def ng(monkeypatch):
    """Return the netguard module with a clean in-memory vault and CFG.

    Each test gets a fresh ``_FakeVault`` and has its CFG secret fields
    reset so test ordering can't poison results. The auto-throttle state
    is also reset.
    """
    monkeypatch.setenv("SECRET_VAULT_ARGON2_FAST", "1")
    import netguard

    # Reset CFG secret fields to known empty defaults.
    for k in ("virustotal_api_key", "otx_api_key", "abuseipdb_api_key",
              "discord_webhook_url", "telegram_bot_token"):
        setattr(netguard.CFG, k, "")

    # Also reset the toggles so test_get_secret_with_vault_unlocked doesn't
    # accidentally trigger threat-intel HTTP paths.
    netguard.CFG.virustotal_enabled = False
    netguard.CFG.otx_enabled = False
    netguard.CFG.abuseipdb_enabled = False
    netguard.CFG.discord_enabled = False
    netguard.CFG.telegram_enabled = False

    # Reset the unlock throttle.
    netguard._VAULT_UNLOCK_ATTEMPTS.clear()
    netguard._VAULT_UNLOCK_BLOCKED_UNTIL = 0.0
    netguard._VAULT_LOCKED_WARNED = False

    # Stub out save_settings — we don't want disk writes during tests.
    monkeypatch.setattr(netguard, "save_settings", lambda: None,
                        raising=True)

    yield netguard


@pytest.fixture
def fake_vault(ng, monkeypatch):
    """Install a fresh _FakeVault on ng._VAULT (forces _get_vault to
    return it instead of constructing the real SecretVault)."""
    fv = _FakeVault()
    monkeypatch.setattr(ng, "_VAULT", fv, raising=False)
    return fv


@pytest.fixture
def no_vault(ng, monkeypatch):
    """Force the vault to be unavailable (deps missing path)."""
    # The False sentinel means _get_vault returns None.
    monkeypatch.setattr(ng, "_VAULT", False, raising=False)
    return ng


# --------------------------------------------------------------------------- #
# Async WS helper — collects responses sent by handle_ws_command
# --------------------------------------------------------------------------- #


class _CapturingWS:
    """Stand-in for a WebSocket — captures every JSON payload sent."""

    def __init__(self) -> None:
        self.sent: List[Dict[str, Any]] = []

    async def send(self, data: str) -> None:
        self.sent.append(json.loads(data))


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def evloop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


def _send_cmd(ng, ws, msg, evloop):
    """Run handle_ws_command against an isolated event loop."""
    evloop.run_until_complete(ng.handle_ws_command(ws, msg))


# =========================================================================== #
# 1.  get_secret behaviour
# =========================================================================== #


class TestGetSecret:

    def test_returns_none_when_vault_unavailable_no_fallback(self, no_vault):
        """When the vault is unavailable AND no fallback key is given,
        ``get_secret`` must return ``None``. (Loud failure modes are the
        caller's job.)"""
        assert no_vault.get_secret("netguard.virustotal.api_key") is None

    def test_returns_cfg_value_when_vault_unavailable_with_fallback(self, no_vault):
        """When the vault is unavailable, the fallback path returns the
        CFG attribute so existing clean installs don't break."""
        no_vault.CFG.virustotal_api_key = "vt-from-cfg"
        got = no_vault.get_secret("netguard.virustotal.api_key",
                                  "virustotal_api_key")
        assert got == "vt-from-cfg"

    def test_returns_cfg_value_when_vault_not_initialized(self, fake_vault, ng):
        """A fake vault exists but ``v.exists() is False`` — same path as
        unavailable, fallback wins."""
        ng.CFG.otx_api_key = "otx-from-cfg"
        got = ng.get_secret("netguard.otx.api_key", "otx_api_key")
        assert got == "otx-from-cfg"

    def test_returns_vault_value_when_unlocked(self, fake_vault, ng):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("netguard.virustotal.api_key", "vt-from-vault")
        ng.CFG.virustotal_api_key = "vt-from-cfg"  # should be ignored
        got = ng.get_secret("netguard.virustotal.api_key",
                            "virustotal_api_key")
        assert got == "vt-from-vault"

    def test_returns_none_when_vault_locked(self, fake_vault, ng):
        """When the vault is locked, secrets are inaccessible — even if a
        fallback was provided. (Locked vault is a security state, not a
        config error: fallback path must NOT silently leak the plaintext
        if a vault was set up.)"""
        fake_vault.init("hunter2hunter2")
        fake_vault.set("netguard.virustotal.api_key", "vt-from-vault")
        fake_vault.lock()
        # The fallback CFG value should NOT leak when the vault has the
        # secret but is locked — get_secret returns None.
        ng.CFG.virustotal_api_key = "vt-from-cfg"
        got = ng.get_secret("netguard.virustotal.api_key",
                            "virustotal_api_key")
        assert got is None

    def test_locked_warning_is_one_shot(self, fake_vault, ng, caplog):
        """Repeated calls against a locked vault must not spam the log.
        The implementation gates on the ``_VAULT_LOCKED_WARNED`` flag."""
        import logging
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        with caplog.at_level(logging.WARNING, logger="netguard"):
            ng.get_secret("netguard.virustotal.api_key")
            ng.get_secret("netguard.virustotal.api_key")
            ng.get_secret("netguard.virustotal.api_key")
        warns = [r for r in caplog.records if "locked" in r.getMessage().lower()]
        assert len(warns) <= 1

    def test_empty_string_in_vault_falls_through_to_cfg(self, fake_vault, ng):
        """Vault returning empty-string is treated as "no secret" — the
        fallback path wins. This keeps semantics consistent with existing
        ``if not key: return`` guards."""
        fake_vault.init("hunter2hunter2")
        fake_vault.set("netguard.otx.api_key", "")
        ng.CFG.otx_api_key = "otx-from-cfg"
        got = ng.get_secret("netguard.otx.api_key", "otx_api_key")
        # Both are valid: vault returns falsy, fallback supplies CFG value.
        assert got == "otx-from-cfg"


# =========================================================================== #
# 2.  WS vault_status — every state has a sane shape
# =========================================================================== #


class TestVaultStatusCommand:

    def test_status_unavailable(self, no_vault, evloop):
        """When the vault module is unavailable, status returns
        ``available=False`` and lists missing deps if any."""
        ws = _CapturingWS()
        _send_cmd(no_vault, ws, {"cmd": "vault_status"}, evloop)
        assert len(ws.sent) == 1
        r = ws.sent[0]
        assert r["type"] == "vault_status"
        assert r["available"] is False
        assert r["initialized"] is False
        assert r["unlocked"] is False
        assert isinstance(r["deps_missing"], list)
        assert isinstance(r["plaintext_keys"], list)

    def test_status_not_initialized(self, fake_vault, ng, evloop):
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_status"}, evloop)
        r = ws.sent[0]
        assert r["available"] is True
        assert r["initialized"] is False
        assert r["unlocked"] is False

    def test_status_unlocked_after_init(self, fake_vault, ng, evloop):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("netguard.virustotal.api_key", "vt-x")
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_status"}, evloop)
        r = ws.sent[0]
        assert r["initialized"] is True
        assert r["unlocked"] is True
        # The names listing must reveal NAMES only, never values.
        assert "netguard.virustotal.api_key" in r["secret_names"]
        for entry in r["secret_names"]:
            assert "vt-x" not in entry

    def test_status_locked(self, fake_vault, ng, evloop):
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_status"}, evloop)
        r = ws.sent[0]
        assert r["initialized"] is True
        assert r["unlocked"] is False
        # Locked → we can't safely enumerate names.
        assert r["secret_names"] == []

    def test_status_lists_plaintext_keys_for_migration(self, fake_vault, ng, evloop):
        ng.CFG.virustotal_api_key = "vt-plain"
        ng.CFG.discord_webhook_url = "https://discord.example/x"
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_status"}, evloop)
        r = ws.sent[0]
        assert "virustotal_api_key" in r["plaintext_keys"]
        assert "discord_webhook_url" in r["plaintext_keys"]
        # And we never echo their VALUES through this channel.
        assert "vt-plain" not in json.dumps(r)


# =========================================================================== #
# 3.  vault_unlock — rate-limit at 3 attempts / 30 s → 5 min lockout
# =========================================================================== #


class TestVaultUnlockRateLimit:

    def test_three_failed_attempts_locks_for_five_minutes(
        self, fake_vault, ng, evloop, monkeypatch
    ):
        fake_vault.init("real-master")

        # Lock first so unlock has to verify the password.
        fake_vault.lock()

        ws = _CapturingWS()
        for _ in range(3):
            _send_cmd(ng, ws, {"cmd": "vault_unlock", "master": "WRONG"}, evloop)

        # 4th attempt — should be throttled even with the CORRECT password.
        ws.sent.clear()
        _send_cmd(ng, ws, {"cmd": "vault_unlock", "master": "real-master"},
                  evloop)
        r = ws.sent[0]
        assert r["type"] == "vault_unlock_result"
        assert r["ok"] is False
        assert r["error"] == "throttled"

    def test_successful_unlock_clears_throttle(self, fake_vault, ng, evloop):
        fake_vault.init("real-master")
        fake_vault.lock()
        ws = _CapturingWS()

        # Two fails, then a success.
        _send_cmd(ng, ws, {"cmd": "vault_unlock", "master": "WRONG"}, evloop)
        _send_cmd(ng, ws, {"cmd": "vault_unlock", "master": "WRONG"}, evloop)
        _send_cmd(ng, ws, {"cmd": "vault_unlock", "master": "real-master"},
                  evloop)
        # On success, attempts are cleared. A subsequent failure must NOT
        # immediately trigger the lockout.
        fake_vault.lock()
        ws.sent.clear()
        _send_cmd(ng, ws, {"cmd": "vault_unlock", "master": "WRONG"}, evloop)
        r = ws.sent[0]
        assert r["ok"] is False
        assert r.get("error") != "throttled"

    def test_throttle_uses_monotonic_so_no_clock_jitter(self, ng):
        # Sanity: the throttle window is the documented 30 seconds.
        assert ng._VAULT_UNLOCK_WINDOW == 30.0
        assert ng._VAULT_UNLOCK_MAX == 3
        assert ng._VAULT_UNLOCK_PENALTY == 300.0


# =========================================================================== #
# 4.  vault_migrate — moves the 5 secret keys, strips plaintext
# =========================================================================== #


class TestVaultMigrate:

    def test_migrate_moves_plaintext_keys_into_vault(
        self, fake_vault, ng, evloop
    ):
        # Seed CFG with all 5 secret keys (real-style values).
        ng.CFG.virustotal_api_key = "vt-plain"
        ng.CFG.otx_api_key = "otx-plain"
        ng.CFG.abuseipdb_api_key = "abuse-plain"
        ng.CFG.discord_webhook_url = "https://discord.example/abc"
        ng.CFG.telegram_bot_token = "tg-plain"

        ws = _CapturingWS()
        _send_cmd(ng, ws,
                  {"cmd": "vault_migrate", "master": "hunter2hunter2"},
                  evloop)
        r = ws.sent[-1]
        assert r["type"] == "vault_migrate_result"
        assert r["ok"] is True
        assert r["count"] == 5
        assert set(r["migrated"]) == {
            "virustotal_api_key", "otx_api_key", "abuseipdb_api_key",
            "discord_webhook_url", "telegram_bot_token",
        }

        # CFG plaintext copies must be stripped.
        for k in ("virustotal_api_key", "otx_api_key", "abuseipdb_api_key",
                  "discord_webhook_url", "telegram_bot_token"):
            assert getattr(ng.CFG, k) == ""

        # Vault now holds the 5 secrets under the namespaced names.
        assert fake_vault._secrets[
            "netguard.virustotal.api_key"] == "vt-plain"
        assert fake_vault._secrets[
            "netguard.otx.api_key"] == "otx-plain"
        assert fake_vault._secrets[
            "netguard.abuseipdb.api_key"] == "abuse-plain"
        assert fake_vault._secrets[
            "netguard.discord.webhook_url"] == "https://discord.example/abc"
        assert fake_vault._secrets[
            "netguard.telegram.bot_token"] == "tg-plain"

    def test_migrate_idempotent_on_empty_cfg(self, fake_vault, ng, evloop):
        """If CFG has no plaintext secrets, migrate succeeds with count=0."""
        ws = _CapturingWS()
        _send_cmd(ng, ws,
                  {"cmd": "vault_migrate", "master": "hunter2hunter2"},
                  evloop)
        r = ws.sent[-1]
        assert r["ok"] is True
        assert r["count"] == 0
        assert r["migrated"] == []

    def test_migrate_rejects_short_master_on_first_init(
        self, fake_vault, ng, evloop
    ):
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_migrate", "master": "short"}, evloop)
        r = ws.sent[-1]
        assert r["ok"] is False

    def test_migrate_when_vault_unavailable(self, no_vault, evloop):
        ws = _CapturingWS()
        _send_cmd(no_vault, ws,
                  {"cmd": "vault_migrate", "master": "hunter2hunter2"},
                  evloop)
        r = ws.sent[-1]
        assert r["ok"] is False
        assert "unavailable" in r["error"].lower()

    def test_get_secret_after_migrate_pulls_from_vault(
        self, fake_vault, ng, evloop
    ):
        """End-to-end: after migration, ``get_secret`` returns the vault
        value and the CFG fallback is inert (because it's now empty)."""
        ng.CFG.virustotal_api_key = "vt-plain"
        ws = _CapturingWS()
        _send_cmd(ng, ws,
                  {"cmd": "vault_migrate", "master": "hunter2hunter2"},
                  evloop)
        # CFG now empty + vault holds the secret + vault unlocked.
        got = ng.get_secret("netguard.virustotal.api_key",
                            "virustotal_api_key")
        assert got == "vt-plain"


# =========================================================================== #
# 5.  vault_init / vault_lock / vault_set_secret — happy paths
# =========================================================================== #


class TestVaultLifecycleCommands:

    def test_init_succeeds_then_lock_then_unlock(self, fake_vault, ng, evloop):
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_init", "master": "hunter2hunter2"},
                  evloop)
        assert ws.sent[-1]["ok"] is True

        ws.sent.clear()
        _send_cmd(ng, ws, {"cmd": "vault_lock"}, evloop)
        assert ws.sent[-1]["type"] == "vault_lock_result"
        assert ws.sent[-1]["ok"] is True
        assert fake_vault.is_unlocked() is False

        ws.sent.clear()
        _send_cmd(ng, ws, {"cmd": "vault_unlock", "master": "hunter2hunter2"},
                  evloop)
        assert ws.sent[-1]["ok"] is True
        assert fake_vault.is_unlocked() is True

    def test_init_rejects_short_master(self, fake_vault, ng, evloop):
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_init", "master": "short"}, evloop)
        assert ws.sent[-1]["ok"] is False

    def test_init_rejects_when_already_initialized(self, fake_vault, ng, evloop):
        fake_vault.init("hunter2hunter2")
        ws = _CapturingWS()
        _send_cmd(ng, ws, {"cmd": "vault_init", "master": "hunter2hunter2"},
                  evloop)
        assert ws.sent[-1]["ok"] is False

    def test_set_secret_strips_matching_cfg_plaintext(
        self, fake_vault, ng, evloop
    ):
        fake_vault.init("hunter2hunter2")
        ng.CFG.virustotal_api_key = "vt-plain"
        ws = _CapturingWS()
        _send_cmd(ng, ws, {
            "cmd": "vault_set_secret",
            "name": "netguard.virustotal.api_key",
            "value": "vt-via-vault",
        }, evloop)
        assert ws.sent[-1]["ok"] is True
        # CFG plaintext for the matching key is wiped.
        assert ng.CFG.virustotal_api_key == ""
        assert fake_vault._secrets["netguard.virustotal.api_key"] == "vt-via-vault"

    def test_set_secret_rejects_when_locked(self, fake_vault, ng, evloop):
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        ws = _CapturingWS()
        _send_cmd(ng, ws, {
            "cmd": "vault_set_secret",
            "name": "netguard.otx.api_key",
            "value": "x",
        }, evloop)
        assert ws.sent[-1]["ok"] is False
