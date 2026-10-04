# Copyright (C) 2026 NetGuard AI Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""Tests for the Argus AI <-> Secret Vault hookup.

Strategy mirrors ``test_secret_vault.py``:

* Real Argon2 is replaced with a fast PBKDF2 stand-in (the vault module
  honours ``SECRET_VAULT_ARGON2_FAST=1`` for cheap test-time cost params,
  but argon2-cffi may be missing entirely in CI — we patch it in just
  like the secret-vault tests).
* The Windows Credential Manager is replaced with an in-memory dict.
* DPAPI is left in whatever state the runner has — the vault gracefully
  degrades when ``win32crypt`` is unavailable.
* Vault root is redirected into ``tmp_path`` via ``SECRET_VAULT_ROOT`` so
  the real ``argus_data/vault/`` is never touched.

Coverage
--------
* migrate_ai_settings_to_vault round-trip (plaintext JSON -> vault).
* save_provider_key + get_provider_key round-trip with vault unlocked.
* Locked vault: get_provider_key falls back to env / JSON / None gracefully.
* JSON file no longer carries plaintext keys after migration.
* Vault dependency missing: degraded mode (no crash, plaintext path works).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Force offscreen for headless CI / sandboxed agent envs.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


# --------------------------------------------------------------------------- #
# Fast deterministic Argon2id stand-in (PBKDF2-SHA256)
# --------------------------------------------------------------------------- #

def _fake_argon2_hash_raw(
    *,
    secret: bytes,
    salt: bytes,
    time_cost: int,
    memory_cost: int,
    parallelism: int,
    hash_len: int,
    type: Any,
) -> bytes:
    iters = max(1, time_cost * 100)
    return hashlib.pbkdf2_hmac(
        "sha256", bytes(secret), bytes(salt), iters, dklen=hash_len
    )


# --------------------------------------------------------------------------- #
# In-memory keyring stand-in
# --------------------------------------------------------------------------- #


class _FakeKeyring:
    def __init__(self) -> None:
        self.store: Dict[tuple, str] = {}

    def get_password(self, service: str, username: str) -> Optional[str]:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, value: str) -> None:
        self.store[(service, username)] = value

    def delete_password(self, service: str, username: str) -> None:
        self.store.pop((service, username), None)


# --------------------------------------------------------------------------- #
# Pytest fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def vault_env(tmp_path, monkeypatch):
    """Redirect SECRET_VAULT_ROOT to tmp_path + cheap Argon2 + clean
    provider env vars so resolution tests aren't fooled by ambient env.
    """
    monkeypatch.setenv("SECRET_VAULT_ROOT", str(tmp_path))
    monkeypatch.setenv("SECRET_VAULT_ARGON2_FAST", "1")
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
              "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    return tmp_path


@pytest.fixture
def hookup(monkeypatch, vault_env):
    """Yield argus_ai_providers with vault deps shimmed in.

    Resets the cached vault singleton so each test gets a fresh instance
    pointed at its own tmp_path.
    """
    import argus_ai_providers as ap
    # Patch the vault module the hookup imports (secret_vault.*).
    import secret_vault as sv

    fake_type = type("FakeType", (), {"ID": "id"})
    monkeypatch.setattr(sv, "_HAS_ARGON2", True, raising=True)
    monkeypatch.setattr(sv, "_argon2_hash_raw",
                        _fake_argon2_hash_raw, raising=True)
    monkeypatch.setattr(sv, "_Argon2Type", fake_type, raising=True)

    fake_kr = _FakeKeyring()
    monkeypatch.setattr(sv, "_HAS_KEYRING", True, raising=True)
    monkeypatch.setattr(sv, "_keyring", fake_kr, raising=True)
    monkeypatch.setattr(sv, "_keyring_errors",
                        type("E", (), {}), raising=True)

    # Force the providers module to consider the vault as "available"
    # even if the import path didn't see argon2 at module-load time.
    monkeypatch.setattr(ap, "_VAULT_AVAILABLE", True, raising=True)
    monkeypatch.setattr(ap, "_secret_vault_mod", sv, raising=True)

    # Point the providers to a fresh vault root inside tmp_path so we
    # don't leak state between cases.
    monkeypatch.setattr(
        ap, "DEFAULT_VAULT_ROOT", vault_env, raising=True
    )
    ap._reset_vault_singleton()

    yield ap

    # Teardown: lock + drop singleton so the next test gets a fresh one.
    try:
        ap.lock_vault()
    except Exception:
        pass
    ap._reset_vault_singleton()


# --------------------------------------------------------------------------- #
# Lifecycle helpers
# --------------------------------------------------------------------------- #


def test_vault_lifecycle_init_unlock_lock(hookup):
    ap = hookup
    # Vault doesn't exist yet.
    assert ap.vault_initialized() is False
    assert ap.is_vault_unlocked() is False

    # init() leaves the vault unlocked per the spec.
    assert ap.init_vault("hunter2-master") is True
    assert ap.vault_initialized() is True
    assert ap.is_vault_unlocked() is True

    ap.lock_vault()
    assert ap.is_vault_unlocked() is False

    # unlock() with the right master.
    assert ap.unlock_vault("hunter2-master") is True
    assert ap.is_vault_unlocked() is True


def test_unlock_with_wrong_master_returns_false(hookup):
    ap = hookup
    ap.init_vault("real-pw")
    ap.lock_vault()
    assert ap.unlock_vault("wrong-pw") is False
    assert ap.is_vault_unlocked() is False


def test_unlock_uninitialized_returns_false(hookup):
    ap = hookup
    assert ap.unlock_vault("anything") is False
    assert ap.is_vault_unlocked() is False


# --------------------------------------------------------------------------- #
# save_provider_key / get_provider_key round-trip
# --------------------------------------------------------------------------- #


def test_save_and_get_provider_key_roundtrip(hookup):
    ap = hookup
    ap.init_vault("master-pw")

    assert ap.save_provider_key("anthropic", "sk-ant-FAKE-12345") is True
    # Cross-check: the secret is reachable via both the convenience
    # function and the lower-level get_secret API.
    assert ap.get_provider_key("anthropic") == "sk-ant-FAKE-12345"
    assert ap.get_secret(ap._vault_name("anthropic")) == "sk-ant-FAKE-12345"


def test_save_provider_key_locked_vault_returns_false(hookup):
    ap = hookup
    ap.init_vault("master-pw")
    ap.lock_vault()
    assert ap.save_provider_key("anthropic", "sk-x") is False


def test_get_provider_key_env_wins_over_vault(hookup, monkeypatch):
    ap = hookup
    ap.init_vault("master-pw")
    ap.save_provider_key("anthropic", "sk-from-vault")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
    assert ap.get_provider_key("anthropic") == "sk-from-env"


def test_get_provider_key_falls_back_to_settings_json(
    hookup, tmp_path, monkeypatch
):
    """When the vault is locked + no env, fall back to plaintext JSON."""
    ap = hookup
    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({"providers": {"openai": {"api_key": "sk-plain"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)
    # Vault not unlocked → JSON fallback path triggers.
    assert ap.get_provider_key("openai") == "sk-plain"


def test_get_provider_key_no_source_returns_none(hookup, monkeypatch):
    ap = hookup
    ap.init_vault("master-pw")
    # No env, no JSON, no vault entry.
    monkeypatch.setattr(
        ap, "DEFAULT_SETTINGS_PATH", Path("/nonexistent/ai_settings.json")
    )
    assert ap.get_provider_key("anthropic") is None


# --------------------------------------------------------------------------- #
# Migration: plaintext JSON -> vault
# --------------------------------------------------------------------------- #


def test_migrate_ai_settings_to_vault_moves_keys(
    hookup, tmp_path, monkeypatch
):
    ap = hookup
    ap.init_vault("master-pw")

    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({
            "provider": "anthropic",
            "providers": {
                "anthropic": {
                    "api_key": "sk-ant-LIVE-1234",
                    "model": "claude-sonnet-4-6",
                },
                "openai": {
                    "api_key": "sk-LIVE-OPENAI",
                    "model": "gpt-4o",
                },
                "google": {
                    "api_key": "AIza-REPLACE-ME",   # placeholder = skipped
                    "model": "gemini-2.0-flash",
                },
            },
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    migrated = ap.migrate_ai_settings_to_vault()
    # Anthropic + OpenAI moved; Google placeholder skipped.
    assert migrated == 2

    # Vault has the real keys.
    assert ap.get_secret(ap._vault_name("anthropic")) == "sk-ant-LIVE-1234"
    assert ap.get_secret(ap._vault_name("openai")) == "sk-LIVE-OPENAI"

    # JSON has been rewritten with markers and no plaintext.
    on_disk = json.loads(settings_path.read_text(encoding="utf-8"))
    anthropic_slot = on_disk["providers"]["anthropic"]
    openai_slot = on_disk["providers"]["openai"]
    google_slot = on_disk["providers"]["google"]

    assert "api_key" not in anthropic_slot
    assert anthropic_slot["api_key_in_vault"] is True
    assert anthropic_slot["model"] == "claude-sonnet-4-6"

    assert "api_key" not in openai_slot
    assert openai_slot["api_key_in_vault"] is True

    # Placeholder left untouched (still in plaintext, no vault marker).
    assert google_slot["api_key"] == "AIza-REPLACE-ME"
    assert "api_key_in_vault" not in google_slot

    # Backup file written.
    backup = settings_path.with_suffix(settings_path.suffix + ".pre-vault.bak")
    assert backup.exists()


def test_migrate_is_idempotent(hookup, tmp_path, monkeypatch):
    ap = hookup
    ap.init_vault("master-pw")
    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({
            "providers": {"anthropic": {"api_key": "sk-ant-MIGRATE-ONCE"}},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    assert ap.migrate_ai_settings_to_vault() == 1
    # Second call: nothing to do.
    assert ap.migrate_ai_settings_to_vault() == 0


def test_migrate_no_op_when_vault_locked(hookup, tmp_path, monkeypatch):
    ap = hookup
    ap.init_vault("master-pw")
    ap.lock_vault()

    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({"providers": {"anthropic": {"api_key": "sk-ant"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    # Vault locked → migration does nothing rather than raising.
    assert ap.migrate_ai_settings_to_vault() == 0
    # Plaintext key still on disk.
    on_disk = json.loads(settings_path.read_text(encoding="utf-8"))
    assert on_disk["providers"]["anthropic"]["api_key"] == "sk-ant"


# --------------------------------------------------------------------------- #
# Plaintext stripping verified end-to-end
# --------------------------------------------------------------------------- #


def test_plaintext_keys_stripped_from_json_after_migration(
    hookup, tmp_path, monkeypatch
):
    """Belt-and-suspenders: scan the rewritten JSON for the literal
    plaintext value to make sure the migration didn't leave it behind in
    a stray field. Catches schema-evolution bugs that would silently
    keep secrets on disk."""
    ap = hookup
    ap.init_vault("master-pw")
    sentinel = "sk-ant-SENSITIVE-DO-NOT-LEAK-ABCDEF"
    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({"providers": {"anthropic": {"api_key": sentinel}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    ap.migrate_ai_settings_to_vault()

    raw = settings_path.read_text(encoding="utf-8")
    assert sentinel not in raw, (
        "plaintext API key must not survive migration in the JSON file"
    )
    # But the .pre-vault.bak still has it (we want a recovery path).
    backup = settings_path.with_suffix(settings_path.suffix + ".pre-vault.bak")
    assert sentinel in backup.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# has_any_api_key sees the vault
# --------------------------------------------------------------------------- #


def test_has_any_api_key_recognises_vault_only_install(
    hookup, tmp_path, monkeypatch
):
    ap = hookup
    ap.init_vault("master-pw")
    ap.save_provider_key("anthropic", "sk-ant-TEST")

    # JSON only carries the marker — no plaintext key.
    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({"providers": {"anthropic": {"api_key_in_vault": True}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    assert ap.has_any_api_key() is True


def test_has_any_api_key_false_when_vault_locked_and_no_env_no_plain(
    hookup, tmp_path, monkeypatch
):
    ap = hookup
    ap.init_vault("master-pw")
    ap.save_provider_key("anthropic", "sk-ant-TEST")
    ap.lock_vault()

    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({"providers": {"anthropic": {"api_key_in_vault": True}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    # No env, no plaintext, vault locked → False (we don't leak vault
    # contents through has_any_api_key when we can't reach them).
    assert ap.has_any_api_key() is False


# --------------------------------------------------------------------------- #
# Degraded mode: vault deps missing
# --------------------------------------------------------------------------- #


def test_degraded_mode_when_vault_unavailable(monkeypatch, tmp_path):
    """Simulate a box without pywin32 / keyring / argon2 — the providers
    module must keep importing and ``get_provider_key`` must fall back
    cleanly to plaintext JSON.
    """
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
              "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(k, raising=False)

    import argus_ai_providers as ap

    monkeypatch.setattr(ap, "_VAULT_AVAILABLE", False, raising=True)
    monkeypatch.setattr(ap, "_secret_vault_mod", None, raising=True)
    ap._reset_vault_singleton()

    # All vault-touching APIs degrade silently to "not available".
    assert ap.vault_initialized() is False
    assert ap.is_vault_unlocked() is False
    assert ap.unlock_vault("anything") is False
    assert ap.init_vault("anything") is False
    assert ap.get_secret("argus.anthropic.api_key") is None
    assert ap.save_provider_key("anthropic", "sk-x") is False
    # Plaintext JSON still works.
    settings_path = tmp_path / "ai_settings.json"
    settings_path.write_text(
        json.dumps({"providers": {"anthropic": {"api_key": "sk-plain"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)
    assert ap.get_provider_key("anthropic") == "sk-plain"

    # Migration is a no-op in degraded mode.
    assert ap.migrate_ai_settings_to_vault() == 0
    # JSON still has the plaintext key (we didn't move it).
    on_disk = json.loads(settings_path.read_text(encoding="utf-8"))
    assert on_disk["providers"]["anthropic"]["api_key"] == "sk-plain"


# --------------------------------------------------------------------------- #
# Compatibility: the upstream get_api_key on a Provider sees the vault
# --------------------------------------------------------------------------- #


def test_provider_get_api_key_consults_vault(hookup):
    ap = hookup
    ap.init_vault("master-pw")
    ap.save_provider_key("openai", "sk-from-vault")

    provider = ap.OpenAIProvider()
    # No JSON key, no env — vault wins.
    assert provider.get_api_key({}) == "sk-from-vault"


def test_provider_get_api_key_settings_wins_over_vault(hookup):
    """Backward compat: a plaintext key in the settings dict still
    resolves first so a partial migration (vault has key + JSON also has
    a stale key) doesn't accidentally reach for the vault until the
    migration completes."""
    ap = hookup
    ap.init_vault("master-pw")
    ap.save_provider_key("openai", "sk-from-vault")

    provider = ap.OpenAIProvider()
    settings = {"providers": {"openai": {"api_key": "sk-from-json"}}}
    assert provider.get_api_key(settings) == "sk-from-json"


# --------------------------------------------------------------------------- #
# AISettingsDialog vault flow (Qt-dependent, optional)
# --------------------------------------------------------------------------- #


def _import_argus_pyqt_then_qapp():
    """Import argus_pyqt FIRST (which imports QtWebEngineWidgets) THEN
    create a QApplication. Qt requires this order. Returns
    (argus_pyqt_module, QApplication) or skips the test if Qt is missing.
    """
    try:
        # Importing argus_pyqt pulls in QtWebEngineWidgets at module
        # level, which must happen before any QCoreApplication exists.
        import argus_pyqt as ap_mod
        from PyQt6.QtWidgets import QApplication
    except Exception as exc:
        pytest.skip(f"argus_pyqt / PyQt6 unavailable: {exc}")
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv[:1])
    return ap_mod, app


def test_dialog_save_uses_vault_when_unlocked(
    hookup, tmp_path, monkeypatch
):
    """When the vault is unlocked at dialog-open time, saving a key
    writes to the vault and the JSON file gets the
    ``api_key_in_vault: true`` marker — no plaintext."""
    ap = hookup
    argus_pyqt, _app = _import_argus_pyqt_then_qapp()
    ap.init_vault("master-pw")  # leaves it unlocked

    settings_path = tmp_path / "ai_settings.json"
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    # Suppress modal prompts so the dialog opens silently — the vault is
    # already unlocked so no prompt is needed anyway, but this guards
    # against the gate seeing a stale state on slow CI.
    argus_pyqt.AISettingsDialog._suppress_vault_prompts = True
    try:
        dlg = argus_pyqt.AISettingsDialog()
        # Vault should be ready since we unlocked above.
        assert dlg._vault_ready is True

        sentinel = "sk-ant-DIALOG-TEST-XYZ"
        dlg._key_edits["anthropic"].setText(sentinel)
        dlg._save_and_close()

        # Vault has the key.
        assert ap.get_secret(ap._vault_name("anthropic")) == sentinel
        # JSON has the marker, NOT the plaintext.
        on_disk = json.loads(settings_path.read_text(encoding="utf-8"))
        anthropic_slot = on_disk["providers"]["anthropic"]
        assert anthropic_slot.get("api_key_in_vault") is True
        assert "api_key" not in anthropic_slot
        # Belt-and-suspenders: raw text does not leak the secret.
        assert sentinel not in settings_path.read_text(encoding="utf-8")
        dlg.deleteLater()
    finally:
        argus_pyqt.AISettingsDialog._suppress_vault_prompts = False


def test_dialog_save_falls_back_to_plaintext_when_vault_locked(
    hookup, tmp_path, monkeypatch
):
    """When the vault is reachable but locked AND no master is supplied
    (suppression flag), the dialog must keep working in degraded plain-
    text mode rather than refusing to save."""
    ap = hookup
    argus_pyqt, _app = _import_argus_pyqt_then_qapp()
    ap.init_vault("master-pw")
    ap.lock_vault()

    settings_path = tmp_path / "ai_settings.json"
    monkeypatch.setattr(ap, "DEFAULT_SETTINGS_PATH", settings_path)

    argus_pyqt.AISettingsDialog._suppress_vault_prompts = True
    try:
        dlg = argus_pyqt.AISettingsDialog()
        # Vault not ready in suppressed mode + locked state.
        assert dlg._vault_ready is False

        dlg._key_edits["openai"].setText("sk-plain-fallback")
        dlg._save_and_close()

        on_disk = json.loads(settings_path.read_text(encoding="utf-8"))
        # Plaintext path used (vault unreachable for this dialog session).
        assert on_disk["providers"]["openai"]["api_key"] == "sk-plain-fallback"
        dlg.deleteLater()
    finally:
        argus_pyqt.AISettingsDialog._suppress_vault_prompts = False
