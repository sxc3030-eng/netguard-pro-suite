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
register_program.py — Whitelist a program with the Argus Vault Gateway.

Interactive CLI: prompts the operator to confirm the binary hash, the
ACL of secrets the program is allowed to read/write, the rate limits,
and a human-readable label. The hash is then handed to
``gateway_register_program``, which appends it to
``argus_data/.gateway/whitelist.json``.

Usage::

    python tools/register_program.py /path/to/my_program.py
    python tools/register_program.py /path/to/my_program.exe --label "My App"

The script never prints any vault values. It only prints metadata.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Make sibling modules importable when invoked directly.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_vault_gateway  # noqa: E402
import argus_vault_manifests  # noqa: E402

try:
    import config as _config_mod  # noqa: E402

    CANONICAL = list(_config_mod.CANONICAL_SECRETS.keys())
except Exception:
    CANONICAL = []


def _confirm(prompt: str, default_yes: bool = True) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    reply = input(f"{prompt} {suffix} ").strip().lower()
    if not reply:
        return default_yes
    return reply in ("y", "yes", "o", "oui")


def _prompt(label: str, default: str = "") -> str:
    if default:
        reply = input(f"{label} [{default}]: ").strip()
        return reply or default
    return input(f"{label}: ").strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="register_program",
        description="Whitelist a program with the Argus Vault Gateway.",
    )
    parser.add_argument(
        "binary_path",
        help="Path to the binary or script to register (its SHA-256 will be "
             "computed and stored).",
    )
    parser.add_argument(
        "--label",
        default=None,
        help="Human-readable label; defaults to the basename.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Auto-confirm hash + secret ACL prompts (for scripted use). "
             "Still requires --secrets.",
    )
    parser.add_argument(
        "--secrets",
        default=None,
        help="Comma-separated list of allowed secret keys, or '*' for all "
             "(use with --yes).",
    )
    parser.add_argument(
        "--permissions",
        default="read",
        help="Comma-separated permissions per secret. Default: read",
    )
    parser.add_argument(
        "--rate-per-min",
        type=int,
        default=60,
        help="Sustained rate limit (requests per minute). Default: 60",
    )
    parser.add_argument(
        "--burst",
        type=int,
        default=10,
        help="Burst size for the token bucket. Default: 10",
    )
    parser.add_argument(
        "--needs",
        default=None,
        help="Comma-separated list of secrets this program is entitled to "
             "read at runtime. 'all' selects every canonical secret, "
             "'none' opts out of every secret. Required with --yes when "
             "no value is given the script falls back to --secrets.",
    )

    args = parser.parse_args(argv)

    binary_path = os.path.abspath(args.binary_path)
    if not os.path.exists(binary_path):
        print(f"ERROR: binary not found: {binary_path}", file=sys.stderr)
        return 2

    print(f"Target binary: {binary_path}")
    print(f"  size: {os.path.getsize(binary_path)} bytes")

    if not args.yes and not _confirm("Compute SHA-256 of this binary?", True):
        print("Aborted.")
        return 1

    try:
        program_hash = argus_vault_gateway._sha256_file(binary_path)
    except OSError as exc:
        print(f"ERROR: hash failed: {exc}", file=sys.stderr)
        return 2
    print(f"  SHA-256: {program_hash}")

    if not args.yes and not _confirm(
        "Confirm the hash matches the expected binary?",
        False,
    ):
        print("Aborted by operator.")
        return 1

    if args.yes and not args.secrets:
        print("ERROR: --yes requires --secrets to be set.", file=sys.stderr)
        return 2

    if args.secrets is not None:
        secrets_csv = args.secrets
    else:
        secrets_csv = _prompt(
            "Allowed secrets (comma-separated, or '*' for all)",
            "*",
        )
    if secrets_csv.strip() == "*":
        allowed = ["*"]
    else:
        allowed = [s.strip() for s in secrets_csv.split(",") if s.strip()]
    if not allowed:
        print("ERROR: no secrets specified.", file=sys.stderr)
        return 2

    perms_csv = (
        args.permissions
        if args.yes
        else _prompt("Permissions (comma-separated, e.g. read,write)", "read")
    )
    perms_list = [p.strip() for p in perms_csv.split(",") if p.strip()]
    if not perms_list:
        perms_list = ["read"]
    permissions = {k: list(perms_list) for k in allowed}

    label = args.label
    if label is None:
        label = (
            os.path.basename(binary_path)
            if args.yes
            else _prompt("Program label (human readable)",
                         os.path.basename(binary_path))
        )

    print()
    print("Summary:")
    print(f"  hash:        {program_hash}")
    print(f"  label:       {label}")
    print(f"  binary:      {binary_path}")
    print(f"  secrets:     {allowed}")
    print(f"  permissions: {permissions}")
    print(f"  rate/min:    {args.rate_per_min}")
    print(f"  burst:       {args.burst}")
    print()

    if not args.yes and not _confirm("Register this program?", False):
        print("Aborted.")
        return 1

    h = argus_vault_gateway.gateway_register_program(
        binary_path=binary_path,
        allowed_secrets=allowed,
        permissions=permissions,
        program_label=label,
        rate_per_min=args.rate_per_min,
        burst=args.burst,
    )
    print(f"OK: program registered with hash {h}")

    # ──────────────────────────────────────────────────────────────────
    # Manifest collection (trust-on-register).
    #
    # Every entry the operator opts in here pre-approves runtime reads
    # for that secret. At runtime, no prompts are raised — calls to
    # ``config.get_secret`` either return the value or None.
    # ──────────────────────────────────────────────────────────────────
    needs_csv = args.needs
    if needs_csv is None and not args.yes:
        if CANONICAL:
            print()
            print("Canonical secrets the suite is aware of:")
            for n in CANONICAL:
                print(f"  - {n}")
        needs_csv = _prompt(
            "Which secrets does this program need? "
            "(comma-separated names, 'all', or 'none')",
            default="none",
        )
    if needs_csv is None:
        # --yes path with no --needs: fall back to whatever was given as
        # --secrets (back-compat) but only the canonical subset; '*' is
        # treated as "no manifest entries" — the operator must be
        # explicit about runtime entitlements.
        if allowed == ["*"]:
            needs_list: list[str] = []
        else:
            needs_list = [s for s in allowed if s in CANONICAL or not CANONICAL]
    else:
        sel = needs_csv.strip().lower()
        if sel == "all":
            needs_list = list(CANONICAL)
        elif sel in ("none", ""):
            needs_list = []
        else:
            raw = [s.strip() for s in needs_csv.split(",") if s.strip()]
            invalid = [s for s in raw if CANONICAL and s not in CANONICAL]
            if invalid:
                print(
                    "WARNING: the following names are not in the canonical "
                    "secret catalogue and will still be accepted (custom "
                    "secrets are allowed): " + ", ".join(invalid),
                    file=sys.stderr,
                )
            needs_list = raw

    try:
        argus_vault_manifests.manifest_set(
            program_hash=h,
            name=label or os.path.basename(binary_path),
            needs=needs_list,
            approved_by="register_program",
        )
    except ValueError as exc:
        print(f"ERROR: manifest rejected: {exc}", file=sys.stderr)
        # The whitelist registration already succeeded; the program will
        # not be entitled to anything until a manifest is set later.
        # Returning a non-zero code lets scripted callers notice.
        return 3

    print(f"OK: manifest stored with {len(needs_list)} secret(s) entitled.")
    if needs_list:
        for n in needs_list:
            print(f"  - {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
