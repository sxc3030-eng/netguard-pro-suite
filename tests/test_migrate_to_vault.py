# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for tools/migrate_to_vault.py.

Each test redirects:
    * the vault root  via ``ARGUS_VAULT_ROOT`` (read by argus_vault)
    * the repo root   via passing ``tmp_path`` directly to ``run_migration``

so the real ``argus_data/.vault`` and the real source files are never
touched.

No real secrets appear in this file — every value is an obvious
placeholder.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import argus_vault  # noqa: E402
import migrate_to_vault as mv  # noqa: E402


PASSPHRASE = "test-passphrase-not-a-real-secret"
TOKEN_PLACEHOLDER = "test_token_placeholder_value_xxxxxxxxxxxx"
LICENSE_PLACEHOLDER = "test_license_placeholder_value_xxxxxxxxx"
ACCOUNT_ID_PLACEHOLDER = "1234567"
API_TOKEN_PLACEHOLDER = "test_api_token_placeholder_value"
HMAC_PLACEHOLDER = "test_hmac_key_placeholder_value_xxxxxxx"
ANTHROPIC_PLACEHOLDER = "sk-ant-test-placeholder-not-real"


@pytest.fixture
def isolated(tmp_path, monkeypatch, capsys):
    """Set up an isolated repo tree + vault for one test."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path / "vault_root"))
    # The migration script reads the passphrase from this env var on
    # PBKDF2-sealed vaults so it can unlock + write without prompting.
    # Tests pin a known placeholder; the real product can be invoked
    # interactively or with a different env var value.
    monkeypatch.setenv("ARGUS_VAULT_PASSPHRASE", PASSPHRASE)
    importlib.reload(argus_vault)
    importlib.reload(mv)

    # Pre-init the vault under a known passphrase so the migration script
    # has a sealed vault to write into. Using PBKDF2 here so the test
    # works on Linux/CI runners that don't have DPAPI available.
    argus_vault.vault_init(passphrase=PASSPHRASE)
    yield tmp_path
    capsys.readouterr()  # drain any noisy output between tests


def _seed_token(repo: Path, name: str = ".netguard_token",
                value: str = TOKEN_PLACEHOLDER) -> Path:
    p = repo / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(value, encoding="utf-8")
    return p


def _seed_maxmind(repo: Path) -> Path:
    g = repo / "geoip"
    g.mkdir(parents=True, exist_ok=True)
    (g / ".maxmind_license").write_text(LICENSE_PLACEHOLDER, encoding="utf-8")
    (g / ".maxmind_account_id").write_text(
        ACCOUNT_ID_PLACEHOLDER, encoding="utf-8"
    )
    return g / ".maxmind_license"


def _vault_has(name: str) -> bool:
    """vault_get with the test passphrase, returning bool."""
    return argus_vault.vault_get(name, passphrase=PASSPHRASE) is not None


# --------------------------------------------------------------------------- #
# Dry run
# --------------------------------------------------------------------------- #


def test_dry_run_makes_no_writes(isolated):
    repo = isolated
    _seed_token(repo)

    counts = mv.run_migration(
        repo_root=repo, auto_yes=True, dry_run=True,
    )
    # Counts are reported but nothing actually written.
    assert counts.migrated == 1
    assert counts.errors == 0

    # Vault must not contain the entry.
    assert argus_vault.vault_get(
        "NETGUARD_WS_TOKEN", passphrase=PASSPHRASE
    ) is None

    # Original file untouched.
    assert (repo / ".netguard_token").exists()


# --------------------------------------------------------------------------- #
# Single-file migration
# --------------------------------------------------------------------------- #


def test_migrate_netguard_token_creates_vault_entry(isolated):
    repo = isolated
    _seed_token(repo)

    counts = mv.run_migration(repo_root=repo, auto_yes=True, dry_run=False)
    assert counts.migrated == 1
    assert counts.errors == 0

    got = argus_vault.vault_get(
        "NETGUARD_WS_TOKEN", passphrase=PASSPHRASE
    )
    assert got == TOKEN_PLACEHOLDER

    # Owner metadata correct.
    listing = {it["name"]: it for it in argus_vault.vault_list()}
    assert listing["NETGUARD_WS_TOKEN"]["owner"] == "netguard"


def test_migrate_maxmind_pair(isolated):
    repo = isolated
    _seed_maxmind(repo)

    counts = mv.run_migration(repo_root=repo, auto_yes=True, dry_run=False)
    assert counts.migrated == 2  # license + account id

    assert (
        argus_vault.vault_get("MAXMIND_LICENSE_KEY", passphrase=PASSPHRASE)
        == LICENSE_PLACEHOLDER
    )
    assert (
        argus_vault.vault_get("MAXMIND_ACCOUNT_ID", passphrase=PASSPHRASE)
        == ACCOUNT_ID_PLACEHOLDER
    )


# --------------------------------------------------------------------------- #
# Missing files
# --------------------------------------------------------------------------- #


def test_migrate_skips_missing_files_gracefully(isolated):
    """Empty repo: migration should run cleanly with zero migrations."""
    counts = mv.run_migration(
        repo_root=isolated, auto_yes=True, dry_run=False,
    )
    assert counts.migrated == 0
    assert counts.errors == 0


# --------------------------------------------------------------------------- #
# Backup behaviour
# --------------------------------------------------------------------------- #


def test_backup_creates_dated_dir(isolated):
    repo = isolated
    _seed_token(repo)

    mv.run_migration(repo_root=repo, auto_yes=True, dry_run=False)

    backup_root = repo / "argus_data"
    backup_dirs = list(backup_root.glob(".migration_backup_*"))
    assert len(backup_dirs) == 1
    assert (backup_dirs[0] / ".netguard_token").exists()


def test_backup_only_does_not_touch_vault(isolated):
    repo = isolated
    _seed_token(repo)

    counts = mv.run_migration(
        repo_root=repo, auto_yes=True, dry_run=False, backup_only=True,
    )
    # Backup-only mode counts as "handled" (=migrated bag) but no vault
    # write occurred.
    assert not _vault_has("NETGUARD_WS_TOKEN")
    # Backup dir exists.
    backup_dirs = list((repo / "argus_data").glob(".migration_backup_*"))
    assert backup_dirs and (backup_dirs[0] / ".netguard_token").exists()
    # And the original is left in place (we only delete in regular mode).
    assert (repo / ".netguard_token").exists()
    assert counts.migrated >= 1  # we count it as handled


# --------------------------------------------------------------------------- #
# Auto-confirm flag
# --------------------------------------------------------------------------- #


def test_yes_flag_skips_prompts(isolated, monkeypatch):
    """``--yes`` must not call ``input``."""
    repo = isolated
    _seed_token(repo)

    def _fail_input(prompt=""):
        raise AssertionError(f"input() should not be called (prompt={prompt!r})")

    monkeypatch.setattr("builtins.input", _fail_input)
    counts = mv.run_migration(repo_root=repo, auto_yes=True, dry_run=False)
    assert counts.migrated == 1


def test_interactive_no_does_not_migrate(isolated, monkeypatch):
    """When the user answers 'n', the source is skipped, not migrated."""
    repo = isolated
    _seed_token(repo)

    monkeypatch.setattr("builtins.input", lambda *a, **k: "n")
    counts = mv.run_migration(repo_root=repo, auto_yes=False, dry_run=False)
    assert counts.migrated == 0
    assert counts.skipped >= 1


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #


def test_idempotent_second_run_is_noop(isolated):
    repo = isolated
    _seed_token(repo)

    first = mv.run_migration(
        repo_root=repo, auto_yes=True, dry_run=False,
    )
    assert first.migrated == 1

    # Re-seed the source (the first run deleted the original after backup).
    _seed_token(repo)
    second = mv.run_migration(
        repo_root=repo, auto_yes=True, dry_run=False,
    )
    # Second pass: every key already lives in the vault.
    assert second.migrated == 0
    assert second.already >= 1


# --------------------------------------------------------------------------- #
# Summary reporting
# --------------------------------------------------------------------------- #


def test_summary_counts(isolated, capsys):
    repo = isolated
    _seed_token(repo)
    _seed_maxmind(repo)

    rc = mv.main(["--yes"])
    out = capsys.readouterr().out
    assert "Summary" in out
    assert "migrated:" in out
    assert "skipped:" in out
    assert "errors:" in out
    assert rc == 0


# --------------------------------------------------------------------------- #
# Secret-leakage guard
# --------------------------------------------------------------------------- #


def test_does_not_log_secret_value(isolated, capsys):
    """Stdout/stderr must NEVER contain a secret value during migration."""
    repo = isolated
    _seed_token(repo, value=TOKEN_PLACEHOLDER)
    _seed_maxmind(repo)

    # Also seed an AI settings file with an "API key".
    (repo / "netguard_ai_settings.json").write_text(
        json.dumps({
            "providers": {
                "anthropic": {"api_key": ANTHROPIC_PLACEHOLDER},
            }
        }),
        encoding="utf-8",
    )

    mv.run_migration(repo_root=repo, auto_yes=True, dry_run=False)
    captured = capsys.readouterr()
    combined = captured.out + captured.err

    for needle in (
        TOKEN_PLACEHOLDER,
        LICENSE_PLACEHOLDER,
        ANTHROPIC_PLACEHOLDER,
    ):
        assert needle not in combined, (
            f"Secret value leaked to console: {needle!r}"
        )


def test_ai_settings_migrates_provider_keys(isolated):
    repo = isolated
    (repo / "netguard_ai_settings.json").write_text(
        json.dumps({
            "providers": {
                "anthropic": {"api_key": ANTHROPIC_PLACEHOLDER},
                "openai":    {"api_key": "sk-openai-test-placeholder"},
            }
        }),
        encoding="utf-8",
    )

    counts = mv.run_migration(repo_root=repo, auto_yes=True, dry_run=False)
    assert counts.migrated == 2
    assert (
        argus_vault.vault_get("ANTHROPIC_API_KEY", passphrase=PASSPHRASE)
        == ANTHROPIC_PLACEHOLDER
    )
    assert (
        argus_vault.vault_get("OPENAI_API_KEY", passphrase=PASSPHRASE)
        == "sk-openai-test-placeholder"
    )
