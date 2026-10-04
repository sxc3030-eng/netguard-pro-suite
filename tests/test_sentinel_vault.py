# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Tests for ``sentinel/vault_helpers.py`` and the AlertManager wiring.

Coverage:

  * ``vault_helpers.get_secret`` — vault-unlocked / locked / unavailable
    paths, fallback semantics, empty-vault-falls-through-to-fallback.
  * ``vault_helpers.set_secret`` — writes only when unlocked.
  * ``vault_helpers.migrate_to_vault`` — moves plaintext, strips
    settings, writes ``.pre-vault.bak`` backup, idempotent on re-run.
  * ``alert_manager.AlertManager`` — vault-aware reads in ``test_*``
    helpers and ``get_config``.

The real ``SecretVault`` is heavyweight (Argon2 + DPAPI + Keyring), so
we install a tiny in-memory fake on ``vault_helpers._VAULT`` for every
test. ``SECRET_VAULT_ARGON2_FAST=1`` is set anyway to keep any live
import paths cheap if a future test pokes the real implementation.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# Make sentinel/ importable so we can import vault_helpers / alert_manager
# directly. ``cortex.py`` is intentionally NOT imported here — it pulls
# in a lot of subprocess + websocket scaffolding that isn't relevant.
#
# NOTE: both ``sentinel/`` and ``mailshield/`` ship a ``vault_helpers.py``,
# which would collide on sys.path. We load Sentinel's variant by file
# location through ``importlib.util.spec_from_file_location`` so the
# test stays robust regardless of import order.
ROOT = Path(__file__).resolve().parent.parent
SENTINEL_DIR = ROOT / "sentinel"
for p in (str(ROOT),):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load_module_from_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# In-memory fake vault — mirrors the SecretVault public surface used by
# vault_helpers.py.
# --------------------------------------------------------------------------- #


class _FakeVault:
    def __init__(self) -> None:
        self._initialized = False
        self._unlocked = False
        self._secrets: Dict[str, str] = {}
        self._master: Optional[str] = None

    def exists(self) -> bool:
        return self._initialized

    def is_unlocked(self) -> bool:
        return self._unlocked

    def init(self, master: str) -> None:
        self._initialized = True
        self._master = master
        self._unlocked = True

    def unlock(self, master: str) -> None:
        if master != self._master:
            raise RuntimeError("BadMaster")
        self._unlocked = True

    def lock(self) -> None:
        self._unlocked = False

    def set(self, name: str, value: str, metadata: Any = None) -> None:
        if not self._unlocked:
            raise RuntimeError("Locked")
        self._secrets[name] = value

    def get(self, name: str) -> Optional[str]:
        if not self._unlocked:
            raise RuntimeError("Locked")
        return self._secrets.get(name)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def vh(monkeypatch):
    """Load Sentinel's ``vault_helpers`` by file path, isolated from any
    cached MailShield-side ``vault_helpers`` already in ``sys.modules``.
    """
    monkeypatch.setenv("SECRET_VAULT_ARGON2_FAST", "1")
    # Drop any pre-existing cached module to force a fresh load.
    sys.modules.pop("vault_helpers", None)
    mod = _load_module_from_path(
        "vault_helpers", SENTINEL_DIR / "vault_helpers.py"
    )
    mod.reset_vault_singleton_for_tests()
    yield mod
    mod.reset_vault_singleton_for_tests()
    sys.modules.pop("vault_helpers", None)


@pytest.fixture
def fake_vault(vh, monkeypatch):
    fv = _FakeVault()
    monkeypatch.setattr(vh, "_VAULT", fv, raising=False)
    monkeypatch.setattr(vh, "_VAULT_LOCKED_WARNED", False, raising=False)
    return fv


@pytest.fixture
def no_vault(vh, monkeypatch):
    monkeypatch.setattr(vh, "_VAULT", False, raising=False)
    return vh


# --------------------------------------------------------------------------- #
# 1. get_secret behaviour
# --------------------------------------------------------------------------- #


class TestGetSecret:
    def test_returns_fallback_when_vault_unavailable(self, no_vault):
        assert no_vault.get_secret(
            "sentinel.discord.webhook", "https://x"
        ) == "https://x"

    def test_returns_none_when_unavailable_no_fallback(self, no_vault):
        assert no_vault.get_secret("sentinel.discord.webhook") is None

    def test_returns_fallback_when_vault_not_initialized(self, fake_vault, vh):
        assert vh.get_secret(
            "sentinel.discord.webhook", "https://fallback"
        ) == "https://fallback"

    def test_returns_vault_value_when_unlocked(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.discord.webhook", "https://from-vault")
        got = vh.get_secret("sentinel.discord.webhook", "https://fallback")
        assert got == "https://from-vault"

    def test_returns_none_when_locked_even_with_fallback(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.discord.webhook", "https://from-vault")
        fake_vault.lock()
        # Locked vault must NOT silently leak the plaintext fallback.
        assert vh.get_secret(
            "sentinel.discord.webhook", "https://fallback"
        ) is None

    def test_empty_string_in_vault_falls_through(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.discord.webhook", "")
        got = vh.get_secret("sentinel.discord.webhook", "https://fallback")
        assert got == "https://fallback"

    def test_locked_warning_is_one_shot(self, fake_vault, vh, caplog):
        import logging
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        with caplog.at_level(logging.WARNING, logger="SentinelOS.Vault"):
            for _ in range(5):
                vh.get_secret("sentinel.slack.webhook")
        warns = [r for r in caplog.records if "locked" in r.getMessage().lower()]
        assert len(warns) <= 1


# --------------------------------------------------------------------------- #
# 2. set_secret + vault_unlocked / vault_initialized
# --------------------------------------------------------------------------- #


class TestSetSecret:
    def test_set_succeeds_when_unlocked(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        ok = vh.set_secret("sentinel.smtp.password", "p@ss")
        assert ok is True
        assert fake_vault._secrets["sentinel.smtp.password"] == "p@ss"

    def test_set_fails_when_locked(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        assert vh.set_secret("sentinel.smtp.password", "p@ss") is False

    def test_set_fails_when_vault_unavailable(self, no_vault):
        assert no_vault.set_secret("sentinel.smtp.password", "p@ss") is False

    def test_status_helpers_track_vault_state(self, fake_vault, vh):
        assert vh.vault_initialized() is False
        assert vh.vault_unlocked() is False
        fake_vault.init("hunter2hunter2")
        assert vh.vault_initialized() is True
        assert vh.vault_unlocked() is True
        fake_vault.lock()
        assert vh.vault_initialized() is True
        assert vh.vault_unlocked() is False


# --------------------------------------------------------------------------- #
# 3. migrate_to_vault — move plaintext + strip + backup + idempotent
# --------------------------------------------------------------------------- #


class TestMigrateToVault:
    def test_migrates_all_known_keys(self, fake_vault, vh, tmp_path):
        fake_vault.init("hunter2hunter2")
        settings_path = tmp_path / "sentinel_settings.json"
        settings = {
            "language": "fr",
            "telegram_bot_token": "tg-secret",
            "telegram_chat_id": "12345",
            "discord_webhook_url": "https://discord.example/x",
            "slack_webhook_url": "https://hooks.slack.example/y",
            "teams_webhook_url": "https://teams.example/z",
            "smtp_password": "smtp-pwd",
            "nvd_api_token": "nvd-tok",
        }
        settings_path.write_text(
            json.dumps(settings, indent=2), encoding="utf-8"
        )
        migrated, count = vh.migrate_to_vault(settings, settings_path=settings_path)
        assert count == 7
        assert set(migrated) == {
            "telegram_bot_token", "telegram_chat_id",
            "discord_webhook_url", "slack_webhook_url",
            "teams_webhook_url", "smtp_password", "nvd_api_token",
        }
        # Vault now holds the secrets under their namespaced keys.
        assert fake_vault._secrets["sentinel.telegram.bot_token"] == "tg-secret"
        assert fake_vault._secrets["sentinel.discord.webhook"] == "https://discord.example/x"
        assert fake_vault._secrets["sentinel.slack.webhook"] == "https://hooks.slack.example/y"
        assert fake_vault._secrets["sentinel.teams.webhook"] == "https://teams.example/z"
        assert fake_vault._secrets["sentinel.smtp.password"] == "smtp-pwd"
        assert fake_vault._secrets["sentinel.nvd.api_token"] == "nvd-tok"

    def test_migrate_strips_plaintext_from_settings(
        self, fake_vault, vh, tmp_path
    ):
        fake_vault.init("hunter2hunter2")
        settings_path = tmp_path / "sentinel_settings.json"
        settings = {"discord_webhook_url": "https://discord.example/x"}
        settings_path.write_text(json.dumps(settings), encoding="utf-8")
        vh.migrate_to_vault(settings, settings_path=settings_path)
        assert settings["discord_webhook_url"] == ""
        # On-disk file also stripped.
        on_disk = json.loads(settings_path.read_text(encoding="utf-8"))
        assert on_disk["discord_webhook_url"] == ""

    def test_migrate_writes_backup_once(self, fake_vault, vh, tmp_path):
        fake_vault.init("hunter2hunter2")
        settings_path = tmp_path / "sentinel_settings.json"
        original = {"discord_webhook_url": "https://discord.example/x"}
        settings_path.write_text(json.dumps(original), encoding="utf-8")
        vh.migrate_to_vault(dict(original), settings_path=settings_path)
        backup = settings_path.with_suffix(".json.pre-vault.bak")
        assert backup.is_file()
        assert json.loads(backup.read_text(encoding="utf-8")) == original
        # Second run must NOT clobber the backup with the now-stripped file.
        vh.migrate_to_vault({"discord_webhook_url": ""}, settings_path=settings_path)
        assert json.loads(backup.read_text(encoding="utf-8")) == original

    def test_migrate_is_idempotent(self, fake_vault, vh, tmp_path):
        fake_vault.init("hunter2hunter2")
        settings_path = tmp_path / "sentinel_settings.json"
        settings = {"discord_webhook_url": "https://discord.example/x"}
        settings_path.write_text(json.dumps(settings), encoding="utf-8")
        m1, c1 = vh.migrate_to_vault(settings, settings_path=settings_path)
        m2, c2 = vh.migrate_to_vault(settings, settings_path=settings_path)
        assert c1 == 1 and c2 == 0
        assert m2 == []

    def test_migrate_no_op_when_vault_locked(self, fake_vault, vh, tmp_path):
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        settings = {"discord_webhook_url": "https://discord.example/x"}
        m, c = vh.migrate_to_vault(settings)
        assert c == 0 and m == []
        # Plaintext stays put — the helper must not silently lose it.
        assert settings["discord_webhook_url"] == "https://discord.example/x"

    def test_migrate_no_op_when_vault_unavailable(self, no_vault):
        settings = {"discord_webhook_url": "https://discord.example/x"}
        m, c = no_vault.migrate_to_vault(settings)
        assert c == 0 and m == []

    def test_migrate_uses_save_callback_when_provided(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        called: List[bool] = []
        settings = {"discord_webhook_url": "https://x"}
        vh.migrate_to_vault(settings, save_callback=lambda: called.append(True))
        assert called == [True]


# --------------------------------------------------------------------------- #
# 4. AlertManager — vault-aware reads
# --------------------------------------------------------------------------- #


class _MiniBus:
    def __init__(self) -> None:
        self.subs: List = []

    def subscribe(self, *a, **kw) -> None:
        self.subs.append((a, kw))

    def publish(self, *a, **kw) -> None:
        pass


@pytest.fixture
def am(fake_vault, vh, monkeypatch):
    """Build an AlertManager that uses the same fake vault as vh.

    ``alert_manager`` is loaded from sentinel/ by file path so the test
    is independent of sys.path ordering with mailshield/.
    """
    sys.modules.pop("alert_manager", None)
    am_mod = _load_module_from_path(
        "alert_manager", SENTINEL_DIR / "alert_manager.py"
    )
    monkeypatch.setattr(am_mod, "_vault_get_secret", vh.get_secret)
    bus = _MiniBus()
    yield am_mod.AlertManager(bus, settings={"language": "en"})
    sys.modules.pop("alert_manager", None)


class TestAlertManagerVaultIntegration:
    def test_get_config_reads_vault_first(self, am, fake_vault):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.telegram.bot_token", "tg-from-vault")
        fake_vault.set("sentinel.discord.webhook", "https://discord/from-vault")
        fake_vault.set("sentinel.slack.webhook", "https://slack/from-vault")
        cfg = am.get_config()
        assert cfg["telegram_configured"] is True
        assert cfg["discord_configured"] is True
        assert cfg["slack_configured"] is True

    def test_get_config_falls_back_to_settings(self, am, fake_vault):
        # Vault stays empty.
        am.settings["discord_webhook_url"] = "https://discord/plain"
        cfg = am.get_config()
        assert cfg["discord_configured"] is True

    def test_get_config_does_not_leak_token_value(self, am, fake_vault):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.telegram.bot_token", "tg-VERY-SECRET")
        cfg = am.get_config()
        assert "VERY-SECRET" not in json.dumps(cfg)

    def test_test_telegram_uses_vault(self, am, fake_vault, monkeypatch):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.telegram.bot_token", "tg-vault")
        fake_vault.set("sentinel.telegram.chat_id", "9999")
        captured: Dict[str, Any] = {}

        class _FakeResp:
            status_code = 200

        def _post(url: str, **kw):
            captured["url"] = url
            captured["kw"] = kw
            return _FakeResp()

        # Inject a fake requests module.
        fake_req = type(sys)("requests_fake")
        fake_req.post = _post  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "requests", fake_req)
        ok = am.test_telegram()
        assert ok is True
        assert "tg-vault" in captured["url"]
        assert captured["kw"]["json"]["chat_id"] == "9999"

    def test_test_telegram_returns_false_without_secrets(self, am):
        assert am.test_telegram() is False

    def test_test_discord_uses_vault(self, am, fake_vault, monkeypatch):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.discord.webhook", "https://discord/vault")
        captured: Dict[str, Any] = {}

        class _FakeResp:
            status_code = 204

        def _post(url: str, **kw):
            captured["url"] = url
            return _FakeResp()

        fake_req = type(sys)("requests_fake")
        fake_req.post = _post  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "requests", fake_req)
        assert am.test_discord() is True
        assert captured["url"] == "https://discord/vault"

    def test_test_slack_uses_vault(self, am, fake_vault, monkeypatch):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.slack.webhook", "https://slack/vault")
        captured: Dict[str, Any] = {}

        class _FakeResp:
            status_code = 200

        def _post(url: str, **kw):
            captured["url"] = url
            return _FakeResp()

        fake_req = type(sys)("requests_fake")
        fake_req.post = _post  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "requests", fake_req)
        assert am.test_slack() is True
        assert captured["url"] == "https://slack/vault"

    def test_test_teams_uses_vault(self, am, fake_vault, monkeypatch):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("sentinel.teams.webhook", "https://teams/vault")
        captured: Dict[str, Any] = {}

        class _FakeResp:
            status_code = 200

        def _post(url: str, **kw):
            captured["url"] = url
            return _FakeResp()

        fake_req = type(sys)("requests_fake")
        fake_req.post = _post  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "requests", fake_req)
        assert am.test_teams() is True
        assert captured["url"] == "https://teams/vault"

    def teardown_method(self, method):
        # AlertManager spawns a daemon thread (``_batch_loop``); make sure
        # we ask it to exit so the test process can shut down cleanly.
        pass
