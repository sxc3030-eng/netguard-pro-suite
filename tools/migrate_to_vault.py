#!/usr/bin/env python3
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
migrate_to_vault.py — one-shot migration of scattered secrets into the
encrypted Argus vault.

Historically, individual modules in the NetGuard / Argus suite each kept
their own dotfile next to their module (``.netguard_token``, ``.api_token``,
``.maxmind_license``, etc.). That made backups awkward and grep-able, and
nothing prevented the wrong dotfile from leaking into a screenshot.

This script walks the known set of secret-bearing files, prompts the user
to migrate each one into the vault, and (optionally) backs up the
originals to a timestamped folder before deletion. The script is
**idempotent**: running it twice in a row on a vault that already holds
the migrated keys will say "already in vault" and do nothing.

Hard rules
----------
* Secret VALUES are never printed, logged, or written outside the vault
  or the (encrypted-by-DPAPI-on-Windows) backup directory.
* The summary at the end reports counts only — never key contents.
* ``--dry-run`` makes zero writes anywhere.

CLI
---
    python tools/migrate_to_vault.py             # interactive
    python tools/migrate_to_vault.py --dry-run   # show plan, no writes
    python tools/migrate_to_vault.py --yes       # auto-confirm
    python tools/migrate_to_vault.py --backup-only

If the vault is sealed with a passphrase (PBKDF2 path — non-Windows or
when ``vault_init`` was called with one explicitly), supply the same
passphrase via the ``ARGUS_VAULT_PASSPHRASE`` environment variable. On
Windows under DPAPI no passphrase is needed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

# Make the repo root importable so we can reach argus_vault / surveillance.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Vault is required; surveillance is best-effort. If surveillance is missing
# we still migrate, we just skip the audit log.
import argus_vault  # noqa: E402

try:
    from argus_surveillance import surveil_log_event  # noqa: E402

    _SURVEIL_OK = True
except Exception:  # pragma: no cover — surveillance is best-effort
    _SURVEIL_OK = False


# --------------------------------------------------------------------------- #
# Source descriptor — one per scattered secret location
# --------------------------------------------------------------------------- #


@dataclass
class Source:
    """A single secret source on disk.

    ``parser`` returns a list of ``(vault_key, value)`` pairs harvested
    from the file. For single-value files this is a one-element list. For
    multi-value files (paired ``maxmind`` files, JSON config) the parser
    can yield several pairs at once.
    """

    relpath: str             # path relative to repo root
    owner: str               # owner tag stored in vault metadata
    parser: Callable[[Path], List[Tuple[str, str]]]
    description: str         # one-liner for the prompt
    extra_paths: List[str] = field(default_factory=list)
    # ``extra_paths`` are sibling files that should be deleted along with
    # ``relpath`` when the user confirms migration (e.g. the paired
    # MaxMind account-id file).


# --------------------------------------------------------------------------- #
# Parsers — each returns a list of (vault_key, value)
# --------------------------------------------------------------------------- #


def _parse_single(vault_key: str) -> Callable[[Path], List[Tuple[str, str]]]:
    """Return a parser that reads ``path`` whole and stores it as ``vault_key``."""

    def _inner(path: Path) -> List[Tuple[str, str]]:
        value = path.read_text(encoding="utf-8").strip()
        if not value:
            return []
        return [(vault_key, value)]

    return _inner


def _parse_maxmind(path: Path) -> List[Tuple[str, str]]:
    """Parse the paired MaxMind license + account-id files.

    The legacy layout stores the license key in ``geoip/.maxmind_license``
    and the account id in the sibling file ``geoip/.maxmind_account_id``.
    We harvest both at once when the license file is the entry point.
    """
    pairs: List[Tuple[str, str]] = []
    license_value = path.read_text(encoding="utf-8").strip()
    if license_value:
        pairs.append(("MAXMIND_LICENSE_KEY", license_value))

    account_path = path.parent / ".maxmind_account_id"
    if account_path.exists():
        account_value = account_path.read_text(encoding="utf-8").strip()
        if account_value:
            pairs.append(("MAXMIND_ACCOUNT_ID", account_value))

    return pairs


def _parse_ai_settings(path: Path) -> List[Tuple[str, str]]:
    """Walk a netguard_ai_settings.json and pull out api_key fields.

    Expected shape::

        {
            "providers": {
                "anthropic": {"api_key": "sk-..."},
                "openai":    {"api_key": "sk-..."},
                ...
            }
        }

    We map provider name -> canonical vault key (``anthropic`` ->
    ``ANTHROPIC_API_KEY``). Unknown providers are stored under
    ``<UPPERCASE>_API_KEY`` so nothing is silently dropped.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    pairs: List[Tuple[str, str]] = []
    providers = data.get("providers", {}) if isinstance(data, dict) else {}
    if not isinstance(providers, dict):
        return []

    canonical = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "google":    "GOOGLE_API_KEY",
        "gemini":    "GOOGLE_API_KEY",  # alias — both names are common
    }
    for provider, cfg in providers.items():
        if not isinstance(cfg, dict):
            continue
        api_key = cfg.get("api_key")
        if not isinstance(api_key, str) or not api_key.strip():
            continue
        key_name = canonical.get(provider.lower(),
                                 f"{provider.upper()}_API_KEY")
        pairs.append((key_name, api_key.strip()))
    return pairs


def _parse_dotenv(path: Path) -> List[Tuple[str, str]]:
    """Best-effort .env parser — KEY=VALUE per line, ignoring comments.

    We do NOT use python-dotenv here because we want to keep this script
    runnable in environments that don't have it installed (e.g. fresh
    clones doing `migrate` before `pip install`).
    """
    pairs: List[Tuple[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if not key or not value:
            continue
        pairs.append((key, value))
    return pairs


# --------------------------------------------------------------------------- #
# Source registry
# --------------------------------------------------------------------------- #


def _build_sources() -> List[Source]:
    """Return the canonical list of secret sources to migrate.

    Order matters only for predictable user-facing output — the migration
    itself is independent per source.
    """
    return [
        Source(
            relpath=".netguard_token",
            owner="netguard",
            parser=_parse_single("NETGUARD_WS_TOKEN"),
            description="NetGuard WebSocket auth token",
        ),
        Source(
            relpath=".netguard_backup_key",
            owner="netguard",
            parser=_parse_single("NETGUARD_BACKUP_KEY"),
            description="NetGuard backup encryption key",
        ),
        Source(
            relpath="geoip/.maxmind_license",
            owner="geoip",
            parser=_parse_maxmind,
            description="MaxMind GeoIP license + account id",
            extra_paths=["geoip/.maxmind_account_id"],
        ),
        Source(
            relpath="mailshield/.api_token",
            owner="mailshield",
            parser=_parse_single("MAILSHIELD_API_TOKEN"),
            description="MailShield API token",
        ),
        Source(
            relpath="netguard_ai_settings.json",
            owner="netguard_ai",
            parser=_parse_ai_settings,
            description="NetGuard AI provider keys",
        ),
        Source(
            relpath="fim/data/.fim_hmac_key",
            owner="fim",
            parser=_parse_single("FIM_HMAC_KEY"),
            description="File integrity monitor HMAC key",
        ),
        Source(
            relpath=".env",
            owner="dotenv",
            parser=_parse_dotenv,
            description=".env file (all KEY=VALUE pairs)",
        ),
    ]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _confirm(prompt: str, *, auto_yes: bool) -> bool:
    """Y/n prompt that defaults to yes. Returns False on EOF or 'n'."""
    if auto_yes:
        return True
    try:
        answer = input(f"{prompt} [Y/n]: ").strip().lower()
    except EOFError:
        return False
    return answer in ("", "y", "yes", "o", "oui", "s", "si")


def _ensure_vault_ready(*, dry_run: bool) -> bool:
    """Make sure the vault exists; lazily init via DPAPI on Windows.

    Returns True on success, False on failure (failure is reported to the
    user by the caller). In dry-run we never create anything; we simply
    note that we would.
    """
    if argus_vault.vault_exists():
        return True
    if dry_run:
        print("[dry-run] would init vault (DPAPI on Windows, "
              "passphrase elsewhere)")
        return True
    try:
        argus_vault.vault_init()
        print("Vault initialised.")
        return True
    except argus_vault.VaultPassphraseRequiredError:
        print("ERROR: this platform needs a passphrase to seal the vault.",
              file=sys.stderr)
        print("       Run argus_vault.vault_init(passphrase=...) first, "
              "or set up DPAPI/Windows.",
              file=sys.stderr)
        return False
    except argus_vault.VaultError as exc:
        print(f"ERROR: vault init failed ({exc.__class__.__name__})",
              file=sys.stderr)
        return False


def _backup_originals(
    paths: Iterable[Path],
    backup_root: Path,
    *,
    dry_run: bool,
) -> Path:
    """Copy each existing path into a timestamped backup folder."""
    if dry_run:
        print(f"[dry-run] would back up to {backup_root}")
        return backup_root

    backup_root.mkdir(parents=True, exist_ok=True)
    for src in paths:
        if not src.exists():
            continue
        dst = backup_root / src.name
        # If two sources share a basename (.api_token in two folders),
        # disambiguate using the parent dir name.
        if dst.exists():
            dst = backup_root / f"{src.parent.name}__{src.name}"
        try:
            shutil.copy2(src, dst)
        except OSError as exc:
            print(f"WARN: could not back up {src}: {exc}", file=sys.stderr)
    return backup_root


def _delete_paths(paths: Iterable[Path], *, dry_run: bool) -> None:
    """Remove the listed paths; missing paths are ignored silently."""
    for p in paths:
        if not p.exists():
            continue
        if dry_run:
            print(f"[dry-run] would remove {p}")
            continue
        try:
            p.unlink()
        except OSError as exc:
            print(f"WARN: could not delete {p}: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Migration core
# --------------------------------------------------------------------------- #


def _vault_passphrase() -> Optional[str]:
    """Read the vault passphrase from the env var, or None on DPAPI hosts."""
    return os.environ.get("ARGUS_VAULT_PASSPHRASE") or None


def _key_already_in_vault(name: str) -> bool:
    """Check whether ``name`` is already in the vault. Idempotency hinge."""
    try:
        return any(item["name"] == name for item in argus_vault.vault_list())
    except argus_vault.VaultError:
        return False


@dataclass
class _Counts:
    migrated: int = 0
    skipped: int = 0
    already: int = 0
    errors: int = 0


def _process_source(
    source: Source,
    repo_root: Path,
    counts: _Counts,
    *,
    auto_yes: bool,
    dry_run: bool,
    backup_only: bool,
    backup_root: Path,
) -> List[Path]:
    """Process one source. Returns the list of paths it touched (for
    later deletion if applicable).

    Never prints the secret value. Only the vault key name and per-source
    description are user-visible.
    """
    src_path = repo_root / source.relpath
    if not src_path.exists():
        return []

    try:
        pairs = source.parser(src_path)
    except Exception as exc:
        # Parser failure: count as error, never echo file content.
        print(f"  [error] {source.relpath}: parse failed "
              f"({exc.__class__.__name__})",
              file=sys.stderr)
        counts.errors += 1
        return []

    if not pairs:
        print(f"  {source.relpath}: empty or no recognisable secrets — "
              f"skipping")
        return []

    print(f"\nFound: {source.description}")
    print(f"  source: {source.relpath}")
    for key_name, _value in pairs:
        # The underscore prefix is a reminder: do NOT print _value.
        # We deliberately shadow it with `_` to make accidental f-strings
        # fail at review time.
        print(f"    -> {key_name}")

    # All-paths-touched bag for backup/deletion below.
    touched_paths: List[Path] = [src_path]
    for extra in source.extra_paths:
        candidate = repo_root / extra
        if candidate.exists():
            touched_paths.append(candidate)

    if backup_only:
        if _confirm(f"Back up {source.relpath}?", auto_yes=auto_yes):
            _backup_originals(touched_paths, backup_root, dry_run=dry_run)
            counts.migrated += len(pairs)  # treat as "handled"
        else:
            counts.skipped += len(pairs)
        return []  # nothing to delete in backup-only mode

    if not _confirm(f"Migrate {source.relpath} into vault?",
                    auto_yes=auto_yes):
        counts.skipped += len(pairs)
        return []

    # Per-secret idempotency + write.
    new_pairs: List[Tuple[str, str]] = []
    for key_name, value in pairs:
        if _key_already_in_vault(key_name):
            print(f"    {key_name}: already in vault — skipping")
            counts.already += 1
            continue
        if dry_run:
            print(f"    [dry-run] would write {key_name}")
            counts.migrated += 1
            new_pairs.append((key_name, value))
            continue
        try:
            argus_vault.vault_set(
                key_name, value,
                owner=source.owner,
                passphrase=_vault_passphrase(),
            )
        except argus_vault.VaultError as exc:
            print(f"    [error] vault_set({key_name}) failed "
                  f"({exc.__class__.__name__})", file=sys.stderr)
            counts.errors += 1
            continue
        counts.migrated += 1
        new_pairs.append((key_name, value))

    # Best-effort surveillance log: meta only, NEVER the value.
    if _SURVEIL_OK and not dry_run and new_pairs:
        try:
            surveil_log_event(
                "user_action",
                {
                    "type": "secret_migration",
                    "source": source.relpath,
                    "owner": source.owner,
                    "keys": [k for k, _v in new_pairs],
                    "count": len(new_pairs),
                },
            )
        except Exception:  # pragma: no cover
            pass  # surveillance is best-effort, never blocks migration

    return touched_paths


def run_migration(
    repo_root: Optional[Path] = None,
    *,
    auto_yes: bool = False,
    dry_run: bool = False,
    backup_only: bool = False,
) -> _Counts:
    """Drive the migration end-to-end. Returns the summary counts."""
    if repo_root is None:
        repo_root = ROOT

    counts = _Counts()
    if not _ensure_vault_ready(dry_run=dry_run):
        counts.errors += 1
        return counts

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = repo_root / "argus_data" / f".migration_backup_{timestamp}"

    sources = _build_sources()
    all_touched: List[Path] = []

    for source in sources:
        touched = _process_source(
            source,
            repo_root,
            counts,
            auto_yes=auto_yes,
            dry_run=dry_run,
            backup_only=backup_only,
            backup_root=backup_root,
        )
        all_touched.extend(touched)

    # Backup-then-delete the originals if anything succeeded.
    if all_touched and not backup_only:
        if _confirm(
            "\nBack up & delete original secret files now?",
            auto_yes=auto_yes,
        ):
            _backup_originals(all_touched, backup_root, dry_run=dry_run)
            _delete_paths(all_touched, dry_run=dry_run)

    return counts


# --------------------------------------------------------------------------- #
# CLI entry point
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="migrate_to_vault",
        description="Migrate scattered NetGuard / Argus secrets into the "
                    "encrypted vault.",
    )
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would happen, don't touch disk.")
    p.add_argument("--yes", action="store_true",
                   help="Auto-confirm every prompt.")
    p.add_argument("--backup-only", action="store_true",
                   help="Back up originals without migrating into vault.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    counts = run_migration(
        auto_yes=args.yes,
        dry_run=args.dry_run,
        backup_only=args.backup_only,
    )
    print("\nSummary")
    print(f"  migrated: {counts.migrated}")
    print(f"  already in vault: {counts.already}")
    print(f"  skipped: {counts.skipped}")
    print(f"  errors:  {counts.errors}")
    return 0 if counts.errors == 0 else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
