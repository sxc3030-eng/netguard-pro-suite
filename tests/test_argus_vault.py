# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_vault V1.

Each test redirects the vault root to ``tmp_path`` via the
``ARGUS_VAULT_ROOT`` env var, so the real ``argus_data/.vault`` is
never touched. Module-level state in ``argus_vault`` is process-wide;
that's fine because env-var lookup happens on every call.

No real secrets appear in this file. Test values are placeholders only.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

# Make sibling argus_vault.py importable.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_vault  # noqa: E402


PASSPHRASE_PLACEHOLDER = "test-passphrase-not-a-real-secret"
VALUE_PLACEHOLDER = "test_value_xyz"


@pytest.fixture(autouse=True)
def isolated_vault_root(tmp_path, monkeypatch):
    """Redirect every vault op into a per-test tmp dir."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    # Reload not strictly needed (env is read per-call) but cheap insurance:
    importlib.reload(argus_vault)
    yield tmp_path


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _init_with_pbkdf2() -> None:
    """Force the PBKDF2 path even on Windows by passing a passphrase."""
    assert argus_vault.vault_init(passphrase=PASSPHRASE_PLACEHOLDER) is True


# --------------------------------------------------------------------------- #
# Init
# --------------------------------------------------------------------------- #


def test_init_creates_vault(tmp_path):
    assert argus_vault.vault_exists() is False
    created = argus_vault.vault_init(passphrase=PASSPHRASE_PLACEHOLDER)
    assert created is True
    assert argus_vault.vault_exists() is True

    vault_file = tmp_path / ".vault" / "secrets.enc"
    assert vault_file.exists()
    body = json.loads(vault_file.read_text(encoding="utf-8"))
    assert body["version"] == 1
    assert body["wrap_method"] == "pbkdf2"
    assert "wrapped_key" in body
    assert "kdf_salt" in body
    assert body["kdf_iterations"] == 600_000
    assert body["secrets"] == {}


def test_init_idempotent_does_not_overwrite():
    assert argus_vault.vault_init(passphrase=PASSPHRASE_PLACEHOLDER) is True
    argus_vault.vault_set("k1", VALUE_PLACEHOLDER,
                          passphrase=PASSPHRASE_PLACEHOLDER)

    # Second init must NOT clobber the existing vault.
    second = argus_vault.vault_init(passphrase="another-passphrase")
    assert second is False

    # Original secret still retrievable with the original passphrase.
    got = argus_vault.vault_get("k1", passphrase=PASSPHRASE_PLACEHOLDER)
    assert got == VALUE_PLACEHOLDER


# --------------------------------------------------------------------------- #
# Set / Get
# --------------------------------------------------------------------------- #


def test_set_get_roundtrip():
    _init_with_pbkdf2()
    argus_vault.vault_set("api_key", VALUE_PLACEHOLDER, owner="netguard",
                          passphrase=PASSPHRASE_PLACEHOLDER)
    assert (
        argus_vault.vault_get("api_key", passphrase=PASSPHRASE_PLACEHOLDER)
        == VALUE_PLACEHOLDER
    )


def test_get_missing_returns_none():
    _init_with_pbkdf2()
    assert (
        argus_vault.vault_get("does_not_exist",
                              passphrase=PASSPHRASE_PLACEHOLDER)
        is None
    )


# --------------------------------------------------------------------------- #
# Delete
# --------------------------------------------------------------------------- #


def test_delete_existing_returns_true():
    _init_with_pbkdf2()
    argus_vault.vault_set("k1", VALUE_PLACEHOLDER,
                          passphrase=PASSPHRASE_PLACEHOLDER)
    assert argus_vault.vault_delete("k1") is True
    assert (
        argus_vault.vault_get("k1", passphrase=PASSPHRASE_PLACEHOLDER) is None
    )


def test_delete_missing_returns_false():
    _init_with_pbkdf2()
    assert argus_vault.vault_delete("ghost") is False


# --------------------------------------------------------------------------- #
# List — must NEVER include values
# --------------------------------------------------------------------------- #


def test_list_returns_metadata_only():
    _init_with_pbkdf2()
    argus_vault.vault_set("k1", VALUE_PLACEHOLDER, owner="argus",
                          passphrase=PASSPHRASE_PLACEHOLDER)
    argus_vault.vault_set("k2", "another_test_placeholder", owner="genia",
                          passphrase=PASSPHRASE_PLACEHOLDER)

    items = argus_vault.vault_list()
    assert len(items) == 2

    names = {it["name"] for it in items}
    assert names == {"k1", "k2"}

    for it in items:
        assert "value" not in it
        assert "ciphertext_b64" not in it
        assert "nonce_b64" not in it
        assert it["owner"] in {"argus", "genia"}
        assert "created_at" in it
        # Sanity: no test placeholder leaked into any field.
        for v in it.values():
            assert VALUE_PLACEHOLDER not in str(v)
            assert "another_test_placeholder" not in str(v)


# --------------------------------------------------------------------------- #
# Corruption
# --------------------------------------------------------------------------- #


def test_corrupted_file_raises(tmp_path):
    _init_with_pbkdf2()
    vault_file = tmp_path / ".vault" / "secrets.enc"
    vault_file.write_text("{ not valid json", encoding="utf-8")

    with pytest.raises(argus_vault.VaultCorruptedError):
        argus_vault.vault_get("anything",
                              passphrase=PASSPHRASE_PLACEHOLDER)

    # Truncated/invalid header should also raise.
    vault_file.write_text(json.dumps({"version": 999}), encoding="utf-8")
    with pytest.raises(argus_vault.VaultCorruptedError):
        argus_vault.vault_list()


# --------------------------------------------------------------------------- #
# PBKDF2 fallback path
# --------------------------------------------------------------------------- #


def test_passphrase_fallback(tmp_path):
    """Passing a passphrase forces PBKDF2 wrap regardless of platform."""
    _init_with_pbkdf2()

    body = json.loads(
        (tmp_path / ".vault" / "secrets.enc").read_text(encoding="utf-8")
    )
    assert body["wrap_method"] == "pbkdf2"
    assert "kdf_salt" in body
    assert body["kdf_iterations"] == 600_000

    # Round-trip succeeds with correct passphrase.
    argus_vault.vault_set("k", VALUE_PLACEHOLDER,
                          passphrase=PASSPHRASE_PLACEHOLDER)
    assert (
        argus_vault.vault_get("k", passphrase=PASSPHRASE_PLACEHOLDER)
        == VALUE_PLACEHOLDER
    )

    # Wrong passphrase must fail with a generic error — and never echo
    # the passphrase.
    bad = "wrong-passphrase-placeholder"
    with pytest.raises(argus_vault.VaultCorruptedError) as exc_info:
        argus_vault.vault_get("k", passphrase=bad)
    msg = str(exc_info.value)
    assert bad not in msg
    assert PASSPHRASE_PLACEHOLDER not in msg
    assert VALUE_PLACEHOLDER not in msg


# --------------------------------------------------------------------------- #
# Rotation
# --------------------------------------------------------------------------- #


def test_rotate_masterkey_preserves_secrets():
    _init_with_pbkdf2()
    argus_vault.vault_set("a", "value_a_placeholder",
                          passphrase=PASSPHRASE_PLACEHOLDER)
    argus_vault.vault_set("b", "value_b_placeholder", owner="netguard",
                          passphrase=PASSPHRASE_PLACEHOLDER)

    new_pass = "rotated-passphrase-placeholder"
    argus_vault.vault_rotate_masterkey(
        new_passphrase=new_pass,
        old_passphrase=PASSPHRASE_PLACEHOLDER,
    )

    # Old passphrase must no longer work.
    with pytest.raises(argus_vault.VaultCorruptedError):
        argus_vault.vault_get("a", passphrase=PASSPHRASE_PLACEHOLDER)

    # New passphrase reads the same plaintexts back.
    assert argus_vault.vault_get("a", passphrase=new_pass) == "value_a_placeholder"
    assert argus_vault.vault_get("b", passphrase=new_pass) == "value_b_placeholder"

    # Owner metadata is preserved.
    items = {it["name"]: it for it in argus_vault.vault_list()}
    assert items["b"]["owner"] == "netguard"
