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
Argus Vault Manifests — per-program entitlement records.

Implements the **trust-on-register** half of the entitlement design:

* When a program is registered (via ``tools/register_program.py`` or the
  Argus Settings UI) the operator pre-approves the list of secrets the
  program is allowed to read. That list is the *manifest*.
* At runtime, no prompts are ever raised. Calling code goes through
  ``config.get_secret(name)`` (a "lazy" wrapper) and either gets the
  value or ``None``. The caller is expected to handle ``None``
  gracefully — disable the feature, surface a settings link, never
  crash.
* The Settings panel surfaces *auto-routing intelligence*: when the user
  adds a brand new secret, the UI computes which already-registered
  programs WOULD gain read access (because their manifest lists the
  name), and the user clicks Save / Customize to confirm.

Storage model
-------------
* Each manifest lives at
  ``argus_data/.gateway/manifests/<program_hash>.json`` (gitignored via
  ``argus_data/*``).
* The on-disk record is::

      {
        "program_hash": "<64-hex sha256 of the binary>",
        "name":         "Human readable label",
        "needs":        ["ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY"],
        "approved_at":  "2026-04-28T18:00:00+00:00",
        "approved_by":  "user"
      }

* Writes are atomic (``.tmp`` + ``os.replace``) so a crash mid-write
  cannot leave a half-written manifest.
* Reads return ``None`` on any I/O or parse error rather than raising,
  so callers never crash because the manifest dir was wiped.

Public API (module-level — no class needed):

    manifest_set(program_hash, name, needs)        -> None
    manifest_get(program_hash)                     -> Optional[dict]
    manifest_list()                                -> list[dict]
    manifest_delete(program_hash)                  -> bool
    manifest_is_entitled(program_hash, secret)     -> bool
    programs_entitled_to(secret_name)              -> list[dict]

Validation
----------
* ``program_hash`` MUST match ``^[0-9a-f]{64}$`` (SHA-256 hex).
* ``needs`` entries MUST be strings; entries are silently de-duplicated
  and stripped. Empty entries are rejected.
* No call accepts user-supplied paths or filenames — every path goes
  through ``_manifests_dir()`` which is rooted in the gateway state dir.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOG = logging.getLogger("argus.vault_manifests")

# A SHA-256 hex digest is 64 lowercase hex characters. We anchor the
# regex so partial matches like "deadbeef" do not slip through.
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def _gateway_root() -> Path:
    """Resolve the gateway state directory.

    Honours ``ARGUS_VAULT_ROOT`` so tests can redirect storage to
    ``tmp_path``. Mirrors the contract used by ``argus_vault`` and
    ``argus_vault_gateway``.
    """
    override = os.environ.get("ARGUS_VAULT_ROOT")
    if override:
        return Path(override) / ".gateway"
    return Path(__file__).resolve().parent / "argus_data" / ".gateway"


def _manifests_dir() -> Path:
    return _gateway_root() / "manifests"


def _manifest_path(program_hash: str) -> Path:
    """Path to a single manifest. Caller MUST validate the hash first."""
    return _manifests_dir() / f"{program_hash}.json"


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #


def _validate_hash(program_hash: str) -> str:
    """Return the lowercased hash if valid, raise ``ValueError`` otherwise."""
    if not isinstance(program_hash, str):
        raise ValueError("program_hash must be a string")
    h = program_hash.strip().lower()
    if not _HASH_RE.match(h):
        raise ValueError("program_hash must be a 64-char SHA-256 hex digest")
    return h


def _validate_secret_names(needs: List[str]) -> List[str]:
    """Coerce ``needs`` into a clean, deduplicated list of strings.

    The canonical-secret check is layered on top by callers (the manifest
    layer accepts user-defined keys too, since the canonical list is a
    UI catalogue, not a security boundary).
    """
    if not isinstance(needs, list):
        raise ValueError("needs must be a list of secret names")
    cleaned: List[str] = []
    seen: set[str] = set()
    for n in needs:
        if not isinstance(n, str):
            raise ValueError("each entry of needs must be a string")
        s = n.strip()
        if not s:
            raise ValueError("secret names cannot be empty")
        # Reject path separators / suspicious chars early so the caller
        # cannot smuggle a traversal payload into the JSON file.
        if any(c in s for c in ("/", "\\", "\x00", "\n", "\r")):
            raise ValueError(f"secret name contains illegal character: {s!r}")
        if s in seen:
            continue
        seen.add(s)
        cleaned.append(s)
    return cleaned


# --------------------------------------------------------------------------- #
# Atomic file I/O
# --------------------------------------------------------------------------- #


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    """Atomic write: serialize -> write to .tmp -> os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    # Serialize first; if json.dumps raises we have not touched the FS.
    blob = json.dumps(payload, indent=2, sort_keys=True)
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(blob)
    os.replace(tmp, path)


def _read_json_safely(path: Path) -> Optional[Dict[str, Any]]:
    """Return parsed JSON, or None on any I/O / parse error."""
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        _LOG.warning("manifest unreadable at %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        _LOG.warning("manifest at %s is not a JSON object; ignoring", path)
        return None
    return data


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def manifest_set(program_hash: str, name: str, needs: List[str],
                 approved_by: str = "user") -> None:
    """Create or replace a program's manifest.

    Replaces the entire ``needs`` list — there is no partial / merge
    semantic here. Callers that want to add or remove a single secret
    should ``manifest_get``, mutate, and ``manifest_set``.
    """
    h = _validate_hash(program_hash)
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be a non-empty string")
    cleaned_needs = _validate_secret_names(needs)
    record = {
        "program_hash": h,
        "name": name.strip(),
        "needs": cleaned_needs,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "approved_by": str(approved_by) if approved_by is not None else "user",
    }
    _atomic_write_json(_manifest_path(h), record)


def manifest_get(program_hash: str) -> Optional[Dict[str, Any]]:
    """Return the manifest record, or None if missing / unreadable."""
    try:
        h = _validate_hash(program_hash)
    except ValueError:
        return None
    return _read_json_safely(_manifest_path(h))


def manifest_list() -> List[Dict[str, Any]]:
    """Return every registered manifest. Order is filesystem-stable.

    Bad / unreadable files are silently skipped so a single corrupted
    record never blanks out the Settings UI.
    """
    d = _manifests_dir()
    if not d.exists():
        return []
    out: List[Dict[str, Any]] = []
    try:
        entries = sorted(d.iterdir())
    except OSError:
        return []
    for entry in entries:
        if not entry.is_file() or not entry.name.endswith(".json"):
            continue
        rec = _read_json_safely(entry)
        if rec is None:
            continue
        out.append(rec)
    return out


def manifest_delete(program_hash: str) -> bool:
    """Remove a manifest. Returns True iff the file existed before."""
    try:
        h = _validate_hash(program_hash)
    except ValueError:
        return False
    p = _manifest_path(h)
    if not p.exists():
        return False
    try:
        p.unlink()
    except OSError as exc:
        _LOG.warning("could not delete manifest %s: %s", p, exc)
        return False
    return True


def manifest_is_entitled(program_hash: str, secret_name: str) -> bool:
    """Return True iff ``secret_name`` appears in this program's manifest.

    A program with no manifest at all is NOT entitled to anything —
    callers should explicitly call ``manifest_set`` during registration
    to opt the program in.
    """
    if not isinstance(secret_name, str) or not secret_name.strip():
        return False
    rec = manifest_get(program_hash)
    if rec is None:
        return False
    needs = rec.get("needs")
    if not isinstance(needs, list):
        return False
    return secret_name in needs


def programs_entitled_to(secret_name: str) -> List[Dict[str, Any]]:
    """Return every program whose manifest lists ``secret_name``.

    Used by the Settings UI to surface the *auto-routing* preview when
    the operator types a brand-new secret value: "Adding X will grant
    access to: NetGuard, Argus, GeniA". The caller renders this list
    and asks the user to confirm or customize before persisting.
    """
    if not isinstance(secret_name, str) or not secret_name.strip():
        return []
    target = secret_name.strip()
    out: List[Dict[str, Any]] = []
    for rec in manifest_list():
        needs = rec.get("needs", [])
        if isinstance(needs, list) and target in needs:
            out.append(rec)
    return out
