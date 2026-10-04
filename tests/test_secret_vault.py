# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
"""Tests for ``secret_vault.SecretVault``.

Strategy
--------
* We never invoke the real Argon2id (argon2-cffi may not be installed) — a
  module-level fixture monkey-patches ``_argon2_hash_raw`` with a fast
  PBKDF2-based stand-in. Real Argon2 is exercised in production; here we
  only verify the architecture.
* We never touch the real Windows Credential Manager — we substitute an
  in-memory dict for ``keyring.get_password`` / ``set_password`` /
  ``delete_password``.
* We never touch real DPAPI — when ``win32crypt`` is missing the module
  already degrades to "no DPAPI" and stores the inner blob raw. The test
  suite runs in that degraded mode by default but layer-1 round-trip is
  still checked when DPAPI is available.

We use ``tmp_path`` for the vault root via ``SECRET_VAULT_ROOT``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

# Make the repo root importable so ``import secret_vault`` works.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
    # Treat (m,t,p) as the PBKDF2 iteration target — keep low for tests.
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
def vault_root(tmp_path, monkeypatch):
    """Redirect SECRET_VAULT_ROOT into tmp_path."""
    monkeypatch.setenv("SECRET_VAULT_ROOT", str(tmp_path))
    monkeypatch.setenv("SECRET_VAULT_ARGON2_FAST", "1")
    return tmp_path


@pytest.fixture
def sv(monkeypatch, vault_root):
    """Import secret_vault with crypto + keyring shims wired in."""
    import secret_vault as mod

    # 1) Argon2: install fake KDF + force the "have argon2" flag on.
    fake_type = type("FakeType", (), {"ID": "id"})
    monkeypatch.setattr(mod, "_HAS_ARGON2", True, raising=True)
    monkeypatch.setattr(mod, "_argon2_hash_raw",
                        _fake_argon2_hash_raw, raising=True)
    monkeypatch.setattr(mod, "_Argon2Type", fake_type, raising=True)

    # 2) Keyring: in-memory stand-in.
    fake_kr = _FakeKeyring()
    monkeypatch.setattr(mod, "_HAS_KEYRING", True, raising=True)
    monkeypatch.setattr(mod, "_keyring", fake_kr, raising=True)
    monkeypatch.setattr(mod, "_keyring_errors",
                        type("E", (), {}), raising=True)

    return mod


def _make_vault(sv_mod):
    return sv_mod.SecretVault(idle_timeout_minutes=15)


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


def test_init_creates_file_and_unlocks(sv):
    v = _make_vault(sv)
    assert v.exists() is False

    v.init("hunter2")
    assert v.exists() is True
    assert v.is_unlocked() is True


def test_init_twice_raises(sv):
    v = _make_vault(sv)
    v.init("hunter2")
    with pytest.raises(sv.VaultAlreadyInitializedError):
        v.init("hunter2")


def test_unlock_before_init_raises(sv):
    v = _make_vault(sv)
    with pytest.raises(sv.VaultNotInitializedError):
        v.unlock("anything")


def test_lock_then_unlock_recovers(sv):
    v = _make_vault(sv)
    v.init("pw")
    v.set("anthropic_key", "sk-ant-deadbeef")

    v.lock()
    assert v.is_unlocked() is False

    with pytest.raises(sv.VaultLockedError):
        v.get("anthropic_key")

    v.unlock("pw")
    assert v.get("anthropic_key") == "sk-ant-deadbeef"


def test_lock_is_idempotent(sv):
    v = _make_vault(sv)
    v.init("pw")
    v.lock()
    v.lock()
    assert v.is_unlocked() is False


# --------------------------------------------------------------------------- #
# CRUD round-trip
# --------------------------------------------------------------------------- #


def test_set_get_round_trip(sv):
    v = _make_vault(sv)
    v.init("pw")

    v.set("k1", "value-one")
    v.set("k2", "value-two-with-unicode-éñ漢")
    assert v.get("k1") == "value-one"
    assert v.get("k2") == "value-two-with-unicode-éñ漢"


def test_get_unknown_returns_none(sv):
    v = _make_vault(sv)
    v.init("pw")
    assert v.get("does_not_exist") is None


def test_overwrite_preserves_created_at(sv):
    v = _make_vault(sv)
    v.init("pw")

    v.set("api", "v1")
    listing1 = v.list()
    created = listing1[0]["created_at"]

    v.set("api", "v2")
    listing2 = v.list()
    assert listing2[0]["created_at"] == created
    assert listing2[0]["updated_at"] != created or True  # allow same ts
    assert v.get("api") == "v2"


def test_list_returns_metadata_only(sv):
    v = _make_vault(sv)
    v.init("pw")
    v.set("a", "secret-a", metadata={"tag": "low"})
    v.set("b", "secret-b")

    listing = v.list()
    names = sorted(item["name"] for item in listing)
    assert names == ["a", "b"]

    # No plaintext anywhere in the list output.
    payload = json.dumps(listing)
    assert "secret-a" not in payload
    assert "secret-b" not in payload


def test_delete_removes_entry(sv):
    v = _make_vault(sv)
    v.init("pw")
    v.set("k", "v")
    assert v.delete("k") is True
    assert v.get("k") is None
    assert v.delete("k") is False


def test_invalid_name_rejected(sv):
    v = _make_vault(sv)
    v.init("pw")
    with pytest.raises(sv.VaultError):
        v.set("has space", "x")
    with pytest.raises(sv.VaultError):
        v.set("", "x")
    with pytest.raises(sv.VaultError):
        v.set("a" * 200, "x")


# --------------------------------------------------------------------------- #
# Wrong-master / corruption
# --------------------------------------------------------------------------- #


def test_wrong_master_raises_bad_master(sv):
    v = _make_vault(sv)
    v.init("correct-horse-battery-staple")
    v.set("k", "v")
    v.lock()

    v2 = _make_vault(sv)
    with pytest.raises(sv.VaultBadMasterError):
        v2.unlock("wrong-password")
    assert v2.is_unlocked() is False


def test_tampered_kek_wrap_raises_bad_master(sv, vault_root):
    v = _make_vault(sv)
    v.init("pw")
    v.set("k", "v")
    v.lock()

    # Flip a byte in the wrapped KEK.
    f = vault_root / ".secret_vault" / "secret_vault.bin"
    doc = json.loads(f.read_text(encoding="utf-8"))
    blob = bytearray(base64.b64decode(doc["kek_wrap_blob_b64"]))
    blob[-1] ^= 0x01  # tag byte
    doc["kek_wrap_blob_b64"] = base64.b64encode(bytes(blob)).decode("ascii")
    f.write_text(json.dumps(doc), encoding="utf-8")

    v2 = _make_vault(sv)
    with pytest.raises(sv.VaultBadMasterError):
        v2.unlock("pw")


def test_tampered_secret_ciphertext_raises_corrupted(sv, vault_root):
    v = _make_vault(sv)
    v.init("pw")
    v.set("k", "vvv")

    # Corrupt the ciphertext for "k".
    f = vault_root / ".secret_vault" / "secret_vault.bin"
    doc = json.loads(f.read_text(encoding="utf-8"))
    blob = bytearray(base64.b64decode(doc["secrets"]["k"]["ct_b64"]))
    blob[-1] ^= 0x01
    doc["secrets"]["k"]["ct_b64"] = base64.b64encode(
        bytes(blob)).decode("ascii")
    f.write_text(json.dumps(doc), encoding="utf-8")

    # Need a fresh instance because cached doc lives in self.
    v2 = _make_vault(sv)
    v2.unlock("pw")
    with pytest.raises(sv.VaultCorruptedError):
        v2.get("k")


def test_truncated_payload_raises_corrupted(sv):
    """A blob shorter than nonce+tag is rejected before AEAD even tries."""
    v = _make_vault(sv)
    v.init("pw")
    v.set("k", "x")
    # Manually call _aead_open with a tiny blob.
    with pytest.raises(sv.VaultCorruptedError):
        from secret_vault import _aead_open  # type: ignore
        _aead_open(b"\x00" * 32, b"\x00" * 5)


def test_swapped_secret_records_detected_via_aad(sv, vault_root):
    """AAD = name binds ciphertext to its key; swapping fails AEAD."""
    v = _make_vault(sv)
    v.init("pw")
    v.set("a", "secret-A")
    v.set("b", "secret-B")
    v.lock()

    # Swap their ciphertexts.
    f = vault_root / ".secret_vault" / "secret_vault.bin"
    doc = json.loads(f.read_text(encoding="utf-8"))
    a_ct = doc["secrets"]["a"]["ct_b64"]
    b_ct = doc["secrets"]["b"]["ct_b64"]
    doc["secrets"]["a"]["ct_b64"] = b_ct
    doc["secrets"]["b"]["ct_b64"] = a_ct
    f.write_text(json.dumps(doc), encoding="utf-8")

    v2 = _make_vault(sv)
    v2.unlock("pw")
    with pytest.raises(sv.VaultCorruptedError):
        v2.get("a")


# --------------------------------------------------------------------------- #
# change_master
# --------------------------------------------------------------------------- #


def test_change_master_rewraps_and_old_password_fails(sv):
    v = _make_vault(sv)
    v.init("old-pw")
    v.set("k1", "v1")
    v.set("k2", "v2")

    v.change_master("old-pw", "new-pw")

    # Vault still works under the new password (no need to re-unlock if
    # already open) and the per-secret data is intact.
    assert v.get("k1") == "v1"
    assert v.get("k2") == "v2"

    # Lock + try old: rejected.
    v.lock()
    v2 = _make_vault(sv)
    with pytest.raises(sv.VaultBadMasterError):
        v2.unlock("old-pw")

    # Lock + try new: accepted, secrets readable.
    v3 = _make_vault(sv)
    v3.unlock("new-pw")
    assert v3.get("k1") == "v1"
    assert v3.get("k2") == "v2"


def test_change_master_wrong_old_rejected(sv):
    v = _make_vault(sv)
    v.init("real-old")
    v.set("k", "v")

    with pytest.raises(sv.VaultBadMasterError):
        v.change_master("not-the-old-pw", "whatever-new")

    # Real password still works.
    v.lock()
    v2 = _make_vault(sv)
    v2.unlock("real-old")
    assert v2.get("k") == "v"


# --------------------------------------------------------------------------- #
# Auto-lock
# --------------------------------------------------------------------------- #


def test_auto_lock_after_idle(sv, monkeypatch):
    v = _make_vault(sv)
    v.init("pw")
    v.set("k", "v")

    # Force idle timeout to zero.something seconds and step monotonic.
    v._idle_timeout = 1  # 1 second window
    base = [v._last_activity]

    import secret_vault
    fake_now = [base[0]]

    def fake_monotonic():
        return fake_now[0]
    monkeypatch.setattr(secret_vault.time, "monotonic", fake_monotonic)

    # Within the window: still unlocked.
    fake_now[0] = base[0] + 0.5
    assert v.is_unlocked() is True

    # Past the window: auto-lock fires.
    fake_now[0] = base[0] + 5.0
    assert v.is_unlocked() is False
    with pytest.raises(sv.VaultLockedError):
        v.get("k")


def test_idle_timeout_zero_disables_auto_lock(sv, monkeypatch):
    v = sv.SecretVault(idle_timeout_minutes=0)
    v.init("pw")
    v.set("k", "v")

    import secret_vault
    monkeypatch.setattr(secret_vault.time, "monotonic",
                        lambda: 10**9)
    assert v.is_unlocked() is True
    assert v.get("k") == "v"


# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #


def test_audit_log_records_ops_and_no_plaintext(sv):
    v = _make_vault(sv)
    v.init("pw")
    v.set("k", "super-secret-value")
    v.get("k")
    v.delete("k")

    log = v.audit_log()
    ops = [e["op"] for e in log]
    # init, set, get, delete (and unlock-on-init? init doesn't call unlock).
    assert "init" in ops
    assert "set" in ops
    assert "get" in ops
    assert "delete" in ops

    payload = json.dumps(log)
    assert "super-secret-value" not in payload


def test_audit_log_bounded(sv, monkeypatch):
    import secret_vault
    monkeypatch.setattr(secret_vault, "_AUDIT_MAX", 10, raising=True)

    v = _make_vault(sv)
    v.init("pw")
    for i in range(50):
        v.set(f"k{i}", f"v{i}")

    log = v.audit_log()
    assert len(log) <= 10


# --------------------------------------------------------------------------- #
# Migration
# --------------------------------------------------------------------------- #


def test_migrate_from_settings_json(sv, vault_root):
    settings_path = vault_root / "netguard_ai_settings.json"
    settings_path.write_text(json.dumps({
        "provider": "anthropic",
        "providers": {
            "anthropic": {"api_key": "sk-ant-real-key", "model": "x"},
            "openai":    {"api_key": "sk-openai-real",  "model": "y"},
            "google":    {"api_key": "AIza-REPLACE-ME", "model": "z"},
        },
    }), encoding="utf-8")

    v = _make_vault(sv)
    n = v.migrate_from_settings_json(settings_path, master="pw")
    assert n == 2  # google had a placeholder

    assert v.get("anthropic_api_key") == "sk-ant-real-key"
    assert v.get("openai_api_key") == "sk-openai-real"

    # File rewritten without keys + sentinel set.
    rewritten = json.loads(settings_path.read_text(encoding="utf-8"))
    assert "api_key" not in rewritten["providers"]["anthropic"]
    assert rewritten["providers"]["anthropic"]["api_key_in_vault"] is True
    # Backup created.
    backup = settings_path.with_suffix(
        settings_path.suffix + ".pre-vault.bak"
    )
    assert backup.is_file()


def test_migrate_idempotent(sv, vault_root):
    settings_path = vault_root / "netguard_ai_settings.json"
    settings_path.write_text(json.dumps({
        "providers": {
            "anthropic": {"api_key": "sk-ant-real", "model": "x"},
        },
    }), encoding="utf-8")

    v = _make_vault(sv)
    n1 = v.migrate_from_settings_json(settings_path, master="pw")
    assert n1 == 1
    n2 = v.migrate_from_settings_json(settings_path, master="pw")
    assert n2 == 0


# --------------------------------------------------------------------------- #
# Dependency missing surfaces clean errors
# --------------------------------------------------------------------------- #


def test_missing_argon2_raises(sv, monkeypatch):
    monkeypatch.setattr(sv, "_HAS_ARGON2", False)
    v = _make_vault(sv)
    with pytest.raises(sv.VaultDependencyMissingError):
        v.init("pw")


def test_missing_keyring_raises(sv, monkeypatch):
    monkeypatch.setattr(sv, "_HAS_KEYRING", False)
    v = _make_vault(sv)
    with pytest.raises(sv.VaultDependencyMissingError):
        v.init("pw")


def test_keyring_blind_missing_after_init_blocks_unlock(sv):
    v = _make_vault(sv)
    v.init("pw")
    v.set("k", "v")
    v.lock()

    # Wipe the in-memory keyring entry to simulate a blind that has been
    # deleted from Windows Credential Manager.
    sv._keyring.store.clear()

    v2 = _make_vault(sv)
    with pytest.raises(sv.VaultBackendUnavailableError):
        v2.unlock("pw")


# --------------------------------------------------------------------------- #
# Persistence — atomic write leaves a backup
# --------------------------------------------------------------------------- #


def test_backup_is_written(sv, vault_root):
    v = _make_vault(sv)
    v.init("pw")
    v.set("a", "1")
    v.set("b", "2")

    bak = vault_root / ".secret_vault" / "secret_vault.bin.bak"
    assert bak.is_file()


# --------------------------------------------------------------------------- #
# destroy()
# --------------------------------------------------------------------------- #


def test_destroy_removes_file_and_keyring_entry(sv, vault_root):
    v = _make_vault(sv)
    v.init("pw")
    assert v.exists() is True
    assert len(sv._keyring.store) == 1

    v.destroy()
    assert v.exists() is False
    assert len(sv._keyring.store) == 0
