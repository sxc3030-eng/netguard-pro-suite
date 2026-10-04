# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_vault_manifests.

The manifest layer stores per-program entitlement records. Tests
redirect storage to ``tmp_path`` via the ``ARGUS_VAULT_ROOT`` env var
(same convention as test_argus_vault.py and test_argus_vault_gateway.py)
so the real ``argus_data/.gateway/manifests/`` is never touched.

No real secrets — placeholders only. The vault is initialised with a
test passphrase via ``vault_init(passphrase=...)`` so the test suite
runs identically on Windows + Linux CI.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

# Make sibling modules importable.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_vault  # noqa: E402
import argus_vault_manifests as avm  # noqa: E402

PASSPHRASE = "test_passphrase_xyz"
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def isolated_root(tmp_path, monkeypatch):
    """Redirect ARGUS_VAULT_ROOT and reload the modules so that
    ``_manifests_dir()`` resolves under tmp_path."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    importlib.reload(argus_vault)
    importlib.reload(avm)
    # Keep the vault initialised with a passphrase so any future test that
    # also touches argus_vault works on Linux CI without DPAPI.
    argus_vault.vault_init(passphrase=PASSPHRASE)
    yield tmp_path


# --------------------------------------------------------------------------- #
# Round-trip
# --------------------------------------------------------------------------- #


def test_manifest_set_get_roundtrip(tmp_path):
    avm.manifest_set(HASH_A, "NetGuard", ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
    rec = avm.manifest_get(HASH_A)
    assert rec is not None
    assert rec["program_hash"] == HASH_A
    assert rec["name"] == "NetGuard"
    assert rec["needs"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    assert "approved_at" in rec
    assert rec["approved_by"] == "user"

    # File on disk has the same shape and is in the expected location.
    p = tmp_path / ".gateway" / "manifests" / f"{HASH_A}.json"
    assert p.exists()
    on_disk = json.loads(p.read_text(encoding="utf-8"))
    assert on_disk == rec


def test_manifest_set_replaces_existing():
    avm.manifest_set(HASH_A, "NetGuard", ["A", "B", "C"])
    avm.manifest_set(HASH_A, "NetGuard 2", ["B"])
    rec = avm.manifest_get(HASH_A)
    assert rec is not None
    assert rec["name"] == "NetGuard 2"
    assert rec["needs"] == ["B"]


def test_manifest_set_dedupes_and_strips():
    avm.manifest_set(
        HASH_A,
        "Argus",
        ["  ANTHROPIC_API_KEY  ", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
    )
    rec = avm.manifest_get(HASH_A)
    assert rec is not None
    assert rec["needs"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]


# --------------------------------------------------------------------------- #
# List
# --------------------------------------------------------------------------- #


def test_manifest_list_returns_all():
    avm.manifest_set(HASH_A, "NetGuard", ["X"])
    avm.manifest_set(HASH_B, "Argus", ["Y"])
    avm.manifest_set(HASH_C, "GeniA", ["X", "Y"])
    items = avm.manifest_list()
    names = sorted(it["name"] for it in items)
    assert names == ["Argus", "GeniA", "NetGuard"]


def test_manifest_list_empty_when_no_manifests():
    assert avm.manifest_list() == []


def test_manifest_list_skips_corrupt_files(tmp_path):
    avm.manifest_set(HASH_A, "OK", ["X"])
    bad = tmp_path / ".gateway" / "manifests" / f"{HASH_B}.json"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("{ not valid json", encoding="utf-8")

    items = avm.manifest_list()
    assert len(items) == 1
    assert items[0]["name"] == "OK"


# --------------------------------------------------------------------------- #
# Delete
# --------------------------------------------------------------------------- #


def test_manifest_delete_returns_true_when_existing():
    avm.manifest_set(HASH_A, "NetGuard", ["X"])
    assert avm.manifest_delete(HASH_A) is True
    assert avm.manifest_get(HASH_A) is None


def test_manifest_delete_returns_false_when_missing():
    assert avm.manifest_delete(HASH_A) is False


def test_manifest_delete_invalid_hash_returns_false():
    assert avm.manifest_delete("not-a-hash") is False


# --------------------------------------------------------------------------- #
# Entitlement
# --------------------------------------------------------------------------- #


def test_is_entitled_true_when_in_needs():
    avm.manifest_set(HASH_A, "NetGuard", ["ANTHROPIC_API_KEY"])
    assert avm.manifest_is_entitled(HASH_A, "ANTHROPIC_API_KEY") is True


def test_is_entitled_false_when_not_in_needs():
    avm.manifest_set(HASH_A, "NetGuard", ["ANTHROPIC_API_KEY"])
    assert avm.manifest_is_entitled(HASH_A, "OPENAI_API_KEY") is False


def test_is_entitled_false_when_no_manifest():
    # No manifest at all => not entitled (trust-on-register; an
    # un-registered program has zero default entitlements).
    assert avm.manifest_is_entitled(HASH_A, "ANTHROPIC_API_KEY") is False


def test_is_entitled_false_for_invalid_inputs():
    avm.manifest_set(HASH_A, "NetGuard", ["X"])
    assert avm.manifest_is_entitled(HASH_A, "") is False
    assert avm.manifest_is_entitled(HASH_A, None) is False  # type: ignore[arg-type]
    assert avm.manifest_is_entitled("", "X") is False


# --------------------------------------------------------------------------- #
# Auto-routing — programs_entitled_to
# --------------------------------------------------------------------------- #


def test_programs_entitled_to_returns_matching():
    avm.manifest_set(HASH_A, "NetGuard", ["ANTHROPIC_API_KEY"])
    avm.manifest_set(HASH_B, "Argus", ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
    avm.manifest_set(HASH_C, "GeniA", ["VIRUSTOTAL_API_KEY"])

    progs = avm.programs_entitled_to("ANTHROPIC_API_KEY")
    names = sorted(p["name"] for p in progs)
    assert names == ["Argus", "NetGuard"]

    progs = avm.programs_entitled_to("OPENAI_API_KEY")
    assert [p["name"] for p in progs] == ["Argus"]

    progs = avm.programs_entitled_to("DOES_NOT_EXIST")
    assert progs == []


def test_programs_entitled_to_empty_string_returns_empty():
    avm.manifest_set(HASH_A, "NetGuard", ["X"])
    assert avm.programs_entitled_to("") == []
    assert avm.programs_entitled_to("   ") == []


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def test_invalid_program_hash_rejected():
    """program_hash must be exactly 64 lowercase hex chars."""
    with pytest.raises(ValueError):
        avm.manifest_set("not-hex-64-chars", "X", ["A"])

    # Wrong length
    with pytest.raises(ValueError):
        avm.manifest_set("a" * 63, "X", ["A"])
    with pytest.raises(ValueError):
        avm.manifest_set("a" * 65, "X", ["A"])

    # Non-hex character
    with pytest.raises(ValueError):
        avm.manifest_set("g" * 64, "X", ["A"])

    # Wrong type
    with pytest.raises(ValueError):
        avm.manifest_set(123, "X", ["A"])  # type: ignore[arg-type]


def test_uppercase_hash_is_normalized_to_lowercase():
    """SHA-256 digests in upper-case still validate; we normalise to lower."""
    upper = "A" * 64
    avm.manifest_set(upper, "Net", ["X"])
    rec = avm.manifest_get(upper)
    assert rec is not None
    assert rec["program_hash"] == "a" * 64


def test_invalid_secret_name_rejected():
    """Empty / non-string / path-laden names are rejected."""
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "X", [""])
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "X", ["   "])
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "X", [123])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "X", ["../escape"])
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "X", ["a\x00b"])
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "X", ["with\nnewline"])

    # needs must be a list
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "X", "ANTHROPIC_API_KEY")  # type: ignore[arg-type]


def test_invalid_name_rejected():
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "", ["X"])
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, "   ", ["X"])
    with pytest.raises(ValueError):
        avm.manifest_set(HASH_A, None, ["X"])  # type: ignore[arg-type]


def test_manifest_get_invalid_hash_returns_none():
    """Validation in manifest_get is *non-fatal* — bad input -> None."""
    assert avm.manifest_get("not-a-hash") is None
    assert avm.manifest_get("") is None


# --------------------------------------------------------------------------- #
# Atomic writes
# --------------------------------------------------------------------------- #


def test_atomic_write_does_not_corrupt(tmp_path, monkeypatch):
    """Even if the second write blows up at the rename step, the first
    record on disk must remain intact."""
    avm.manifest_set(HASH_A, "first", ["X", "Y"])
    p = tmp_path / ".gateway" / "manifests" / f"{HASH_A}.json"
    first_blob = p.read_text(encoding="utf-8")

    real_replace = avm.os.replace

    def boom_replace(src, dst):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(avm.os, "replace", boom_replace)
    with pytest.raises(OSError):
        avm.manifest_set(HASH_A, "second", ["Z"])

    # The original record is still readable.
    assert p.exists()
    assert p.read_text(encoding="utf-8") == first_blob
    rec = json.loads(p.read_text(encoding="utf-8"))
    assert rec["name"] == "first"
    assert rec["needs"] == ["X", "Y"]

    # And no .tmp file lingers visible to the rest of the world (a
    # half-written .tmp may exist; the consumer is the directory listing
    # which only picks up *.json files, so manifest_list is unaffected).
    monkeypatch.setattr(avm.os, "replace", real_replace)
    items = avm.manifest_list()
    assert len(items) == 1
    assert items[0]["name"] == "first"


def test_atomic_write_serialise_failure_leaves_disk_untouched(tmp_path, monkeypatch):
    """If json.dumps raises (object not serialisable), no file is created."""
    p = tmp_path / ".gateway" / "manifests" / f"{HASH_A}.json"
    assert not p.exists()

    # Replace _validate_secret_names so we can smuggle a non-serialisable
    # object past the front-door validators into _atomic_write_json.
    monkeypatch.setattr(avm, "_validate_secret_names", lambda lst: lst)

    class NotJsonable:
        pass

    with pytest.raises(TypeError):
        avm.manifest_set(HASH_A, "X", [NotJsonable()])  # type: ignore[list-item]

    assert not p.exists()
