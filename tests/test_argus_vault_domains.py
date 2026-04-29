# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_vault_domains.

The user-extension JSON path honours ``ARGUS_VAULT_ROOT``, so each test
gets an isolated tmp_path. No real customer data is touched.
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

import argus_vault_domains as vd  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_user_root(tmp_path, monkeypatch):
    """Redirect the user-extension JSON into a per-test tmp dir."""
    monkeypatch.setenv("ARGUS_VAULT_ROOT", str(tmp_path))
    importlib.reload(vd)
    yield tmp_path


# --------------------------------------------------------------------------- #
# Built-in detection
# --------------------------------------------------------------------------- #


def test_known_canadian_bank_matches():
    match = vd.is_vault_domain("https://www.td.com/login")
    assert match is not None
    assert match.institution_name == "TD Canada Trust"
    assert match.category == "bank"

    match2 = vd.is_vault_domain("https://desjardins.com")
    assert match2 is not None
    assert match2.institution_name == "Desjardins"


def test_subdomain_matches():
    """easyweb.td.com must resolve to TD even though it's a subdomain."""
    m = vd.is_vault_domain("https://easyweb.td.com/path?q=1")
    assert m is not None
    assert m.institution_name == "TD Canada Trust"


def test_unknown_domain_returns_none():
    assert vd.is_vault_domain("https://example.com") is None
    assert vd.is_vault_domain("https://en.wikipedia.org") is None
    # Tricky: a host that ends with a vault domain string but isn't a real
    # subdomain (notrbc.com vs rbc.com).
    assert vd.is_vault_domain("https://notrbc.com") is None


def test_url_with_path_query_strips_correctly():
    m = vd.is_vault_domain(
        "https://www.paypal.com/myaccount/transfer?amount=1&token=foo#section"
    )
    assert m is not None
    assert m.category == "payment"
    # Bare host (no scheme) also works.
    m2 = vd.is_vault_domain("coinbase.com")
    assert m2 is not None
    assert m2.category == "crypto"


def test_invalid_url_inputs_safe():
    # Empty / non-string / weird shapes must not crash.
    assert vd.is_vault_domain("") is None
    assert vd.is_vault_domain("   ") is None
    assert vd.is_vault_domain("not a url at all") is None
    assert vd.is_vault_domain(None) is None  # type: ignore[arg-type]


def test_all_institutions_includes_minimum_count():
    """Spec requires at least 25 pre-loaded entries."""
    builtins = vd.all_institutions()
    assert len(builtins) >= 25


def test_all_institutions_all_categories_valid():
    for entry in vd.all_institutions():
        assert entry.category in vd.VALID_CATEGORIES
        assert entry.institution_name
        assert entry.matched_domain


# --------------------------------------------------------------------------- #
# User-extensible registry
# --------------------------------------------------------------------------- #


def test_user_added_institution_matches(tmp_path):
    vd.add_user_institution("Example Credit Union", "bank", "examplecu.ca")
    m = vd.is_vault_domain("https://login.examplecu.ca")
    assert m is not None
    assert m.institution_name == "Example Credit Union"
    assert m.category == "bank"

    # Persistence: the JSON file lives in tmp_path (gitignored in real repo).
    user_file = tmp_path / "vault_domains_user.json"
    assert user_file.exists()
    body = json.loads(user_file.read_text(encoding="utf-8"))
    assert any(e["matched_domain"] == "examplecu.ca" for e in body)


def test_remove_user_institution():
    vd.add_user_institution("Acme Bank", "bank", "acmebank.test")
    assert vd.is_vault_domain("https://acmebank.test") is not None
    assert vd.remove_user_institution("acmebank.test") is True
    assert vd.is_vault_domain("https://acmebank.test") is None
    # Removing again returns False.
    assert vd.remove_user_institution("acmebank.test") is False


def test_all_institutions_includes_user_added():
    builtin_count = len(vd.all_institutions())
    vd.add_user_institution("Local Credit Union", "bank", "localcu.test")
    after = vd.all_institutions()
    assert len(after) == builtin_count + 1
    assert any(e.matched_domain == "localcu.test" for e in after)


def test_add_user_institution_validates_inputs():
    with pytest.raises(ValueError):
        vd.add_user_institution("", "bank", "x.test")
    with pytest.raises(ValueError):
        vd.add_user_institution("X", "not_a_real_category", "x.test")
    with pytest.raises(ValueError):
        vd.add_user_institution("X", "bank", "")


def test_add_user_institution_dedupes_by_domain():
    vd.add_user_institution("First Name", "bank", "samedomain.test")
    vd.add_user_institution("Second Name", "bank", "SAMEDOMAIN.TEST")
    matches = [
        e for e in vd.all_institutions() if e.matched_domain == "samedomain.test"
    ]
    assert len(matches) == 1
    assert matches[0].institution_name == "Second Name"


def test_user_entries_take_precedence_over_builtin():
    """If user adds an alias for a known domain, their label wins."""
    vd.add_user_institution("My TD Override", "bank", "td.com")
    m = vd.is_vault_domain("https://td.com")
    assert m is not None
    assert m.institution_name == "My TD Override"
