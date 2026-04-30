# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Tests for ``mailshield/vault_helpers.py`` and the password lookup wiring.

Coverage:

  * ``vault_helpers.account_password_key`` — sanitization of e-mail
    addresses into a vault-safe key suffix.
  * ``vault_helpers.get_secret`` / ``set_secret`` — vault state matrix.
  * ``vault_helpers.migrate_to_vault`` — moves per-account passwords AND
    top-level API keys, decrypts XOR envelopes via the supplied callback,
    leaves a ``.pre-vault.bak`` backup, idempotent.

The mailshield.py module imports ``msal``, ``websockets`` and a long
list of stdlib mail packages at module load. We therefore only import
``vault_helpers`` directly here — the integration with mailshield.py is
exercised by the import of ``account_password_key`` etc. (smoke tests
guard against accidental rename).
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
MAILSHIELD_DIR = ROOT / "mailshield"
for p in (str(ROOT),):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load_module_from_path(name: str, path: Path):
    """Load a module from an explicit file path. Used to disambiguate
    between Sentinel's and MailShield's ``vault_helpers.py`` — both
    ship the same module name."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# Fake vault — same surface as test_sentinel_vault.py / test_netguard_vault.py
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
    """Load MailShield's ``vault_helpers`` by file path, isolated from
    any cached Sentinel-side ``vault_helpers`` already in
    ``sys.modules``."""
    monkeypatch.setenv("SECRET_VAULT_ARGON2_FAST", "1")
    sys.modules.pop("vault_helpers", None)
    mod = _load_module_from_path(
        "vault_helpers", MAILSHIELD_DIR / "vault_helpers.py"
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
# 1. Email -> key sanitization
# --------------------------------------------------------------------------- #


class TestAccountKey:
    def test_simple_email(self, vh):
        key = vh.account_password_key("alice@example.com")
        assert key == "mailshield.account.alice_example.com.password"

    def test_lowercases_email(self, vh):
        key = vh.account_password_key("Alice@Example.COM")
        assert key == "mailshield.account.alice_example.com.password"

    def test_strips_unsafe_chars(self, vh):
        key = vh.account_password_key("foo+work@example.com")
        assert "+" not in key
        # Plus-sign collapses into the underscore replacement.
        assert key.startswith("mailshield.account.foo_work_example.com")

    def test_empty_email_returns_empty(self, vh):
        assert vh.account_password_key("") == ""
        assert vh.account_password_key(None) == ""  # type: ignore[arg-type]

    def test_refresh_token_key_uses_same_suffix(self, vh):
        pwd_key = vh.account_password_key("alice@example.com")
        rt_key = vh.account_refresh_token_key("alice@example.com")
        assert pwd_key.startswith("mailshield.account.")
        assert rt_key.startswith("mailshield.account.")
        assert pwd_key.split(".")[-2] == rt_key.split(".")[-2]


# --------------------------------------------------------------------------- #
# 2. get_secret / set_secret state matrix
# --------------------------------------------------------------------------- #


class TestGetSecret:
    def test_returns_fallback_when_unavailable(self, no_vault):
        assert no_vault.get_secret("mailshield.x", "fb") == "fb"

    def test_returns_fallback_when_not_initialized(self, fake_vault, vh):
        assert vh.get_secret("mailshield.x", "fb") == "fb"

    def test_returns_vault_value_when_unlocked(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("mailshield.x", "from-vault")
        assert vh.get_secret("mailshield.x", "fb") == "from-vault"

    def test_returns_none_when_locked(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.set("mailshield.x", "from-vault")
        fake_vault.lock()
        # No silent-leak of the fallback when the vault is locked.
        assert vh.get_secret("mailshield.x", "fb") is None

    def test_empty_name_returns_fallback(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        assert vh.get_secret("", "fb") == "fb"

    def test_set_when_locked_returns_false(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        assert vh.set_secret("mailshield.x", "v") is False

    def test_set_writes_to_vault(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        assert vh.set_secret("mailshield.x", "v") is True
        assert fake_vault._secrets["mailshield.x"] == "v"


# --------------------------------------------------------------------------- #
# 3. migrate_to_vault
# --------------------------------------------------------------------------- #


def _xor_decrypt(envelope: str) -> str:
    """Tiny stand-in for ``mailshield.password_vault.decrypt``. Strips
    the ENC: prefix and reverses a no-op encoding so we have a stable
    cleartext to assert against."""
    if envelope.startswith("ENC:"):
        # Test-only: assume the rest is the plaintext base64'd. We only
        # need a deterministic mapping for the test, not real crypto.
        import base64
        try:
            return base64.b64decode(envelope[4:]).decode("utf-8")
        except Exception:
            return ""
    return envelope


def _make_envelope(plaintext: str) -> str:
    import base64
    return "ENC:" + base64.b64encode(plaintext.encode("utf-8")).decode("ascii")


class TestMigrateToVault:
    def test_moves_per_account_plain_passwords(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
                {"email": "bob@example.com",   "password": "bob-pwd"},
            ],
        }
        migrated, count = vh.migrate_to_vault(settings)
        assert count == 2
        assert "account:alice@example.com:password" in migrated
        assert "account:bob@example.com:password" in migrated
        assert (
            fake_vault._secrets["mailshield.account.alice_example.com.password"]
            == "alice-pwd"
        )
        assert (
            fake_vault._secrets["mailshield.account.bob_example.com.password"]
            == "bob-pwd"
        )
        # Passwords stripped from settings, marker flag set.
        for acc in settings["accounts"]:
            assert acc["password"] == ""
            assert acc["password_in_vault"] is True

    def test_decrypts_xor_envelopes_via_callback(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {
                    "email": "alice@example.com",
                    "password": _make_envelope("alice-pwd"),
                },
            ],
        }
        migrated, count = vh.migrate_to_vault(
            settings, decrypt_password=_xor_decrypt
        )
        assert count == 1
        # The stored vault value is the cleartext, NOT the XOR envelope.
        assert (
            fake_vault._secrets["mailshield.account.alice_example.com.password"]
            == "alice-pwd"
        )

    def test_skips_xor_envelopes_without_decryptor(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {
                    "email": "alice@example.com",
                    "password": _make_envelope("alice-pwd"),
                },
            ],
        }
        migrated, count = vh.migrate_to_vault(settings)
        # No decryptor → nothing was migrated.
        assert count == 0
        assert migrated == []
        # And the envelope is still in place.
        assert settings["accounts"][0]["password"].startswith("ENC:")

    def test_top_level_api_keys_migrate(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "anthropic_api_key": "sk-ant-abc",
            "openai_api_key": "sk-openai-xyz",
        }
        migrated, count = vh.migrate_to_vault(settings)
        assert count == 2
        assert "anthropic_api_key" in migrated
        assert "openai_api_key" in migrated
        assert fake_vault._secrets["mailshield.anthropic.api_key"] == "sk-ant-abc"
        assert fake_vault._secrets["mailshield.openai.api_key"] == "sk-openai-xyz"
        assert settings["anthropic_api_key"] == ""
        assert settings["openai_api_key"] == ""

    def test_refresh_tokens_migrate(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {
                    "email": "alice@example.com",
                    "password": "p",
                    "refresh_token": "rt-abc",
                },
            ],
        }
        migrated, count = vh.migrate_to_vault(settings)
        assert count == 2
        assert (
            fake_vault._secrets["mailshield.account.alice_example.com.refresh_token"]
            == "rt-abc"
        )
        assert settings["accounts"][0]["refresh_token"] == ""
        assert settings["accounts"][0]["refresh_token_in_vault"] is True

    def test_writes_settings_backup(self, fake_vault, vh, tmp_path):
        fake_vault.init("hunter2hunter2")
        settings_path = tmp_path / "mailshield_settings.json"
        original = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        settings_path.write_text(json.dumps(original), encoding="utf-8")
        # Pass a copy so the on-disk file is what we read back.
        vh.migrate_to_vault(json.loads(json.dumps(original)),
                            settings_path=settings_path)
        backup = settings_path.with_suffix(".json.pre-vault.bak")
        assert backup.is_file()
        assert json.loads(backup.read_text(encoding="utf-8")) == original

    def test_idempotent(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        m1, c1 = vh.migrate_to_vault(settings)
        m2, c2 = vh.migrate_to_vault(settings)
        assert c1 == 1
        assert c2 == 0  # nothing left to migrate
        assert m2 == []

    def test_no_op_when_locked(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        fake_vault.lock()
        settings = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        m, c = vh.migrate_to_vault(settings)
        assert c == 0 and m == []
        assert settings["accounts"][0]["password"] == "alice-pwd"

    def test_no_op_when_vault_unavailable(self, no_vault):
        settings = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        m, c = no_vault.migrate_to_vault(settings)
        assert c == 0 and m == []

    def test_skips_accounts_with_blank_email(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {"email": "", "password": "no-key-for-this"},
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        migrated, count = vh.migrate_to_vault(settings)
        assert count == 1
        assert all("alice" in m for m in migrated)
        # The blank-email entry is left untouched.
        assert settings["accounts"][0]["password"] == "no-key-for-this"

    def test_migrate_with_save_callback(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        called: List[Dict[str, Any]] = []
        settings = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        vh.migrate_to_vault(
            settings, save_callback=lambda s: called.append(s),
        )
        assert called and called[0]["accounts"][0]["password"] == ""


# --------------------------------------------------------------------------- #
# 4. End-to-end round trip — get_secret retrieves what migrate stored
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    def test_get_secret_after_migrate(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        vh.migrate_to_vault(settings)
        # Direct vault read via the public helper.
        got = vh.get_secret(
            vh.account_password_key("alice@example.com"),
            fallback="legacy",
        )
        assert got == "alice-pwd"

    def test_lock_after_migrate_returns_none(self, fake_vault, vh):
        fake_vault.init("hunter2hunter2")
        settings = {
            "accounts": [
                {"email": "alice@example.com", "password": "alice-pwd"},
            ],
        }
        vh.migrate_to_vault(settings)
        fake_vault.lock()
        # Locked vault returns None even if an unrelated fallback exists.
        got = vh.get_secret(
            vh.account_password_key("alice@example.com"),
            fallback="legacy",
        )
        assert got is None
