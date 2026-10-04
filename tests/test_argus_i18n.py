# Copyright (C) 2026 sxc3030-eng
#
# This file is part of the NetGuard / Argus / GeniA / Vinom suite.
# Licensed under the GNU General Public License v3 or later.
# See <https://www.gnu.org/licenses/> for the full text.
"""Tests for argus_i18n.

These tests exercise the JSON loader, the fallback chain, kwargs
formatting, and the locale auto-detection branch. They do NOT touch real
locale state — ``monkeypatch`` redirects ``locale.getlocale`` for the
auto-detect test.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argus_i18n  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_module():
    """Reload argus_i18n between tests so module-level state can't leak.

    The module keeps ``_strings`` and ``_current_lang`` at module scope on
    purpose (cheap singleton). Reloading is the simplest way to give each
    test a clean slate without exposing private setters.
    """
    importlib.reload(argus_i18n)
    yield


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def test_init_loads_3_langs():
    argus_i18n.init("fr")
    langs = argus_i18n.available_langs()
    assert sorted(langs) == ["en", "es", "fr"]


def test_init_default_lang_is_french():
    argus_i18n.init("fr")
    assert argus_i18n.get_lang() == "fr"


# --------------------------------------------------------------------------- #
# Lookup
# --------------------------------------------------------------------------- #


def test_lookup_returns_correct_translation():
    argus_i18n.init("en")
    assert argus_i18n._("app.title") == "Argus"
    assert argus_i18n._("common.cancel") == "Cancel"

    argus_i18n.set_lang("fr")
    assert argus_i18n._("common.cancel") == "Annuler"

    argus_i18n.set_lang("es")
    assert argus_i18n._("common.cancel") == "Cancelar"


def test_missing_key_returns_key_string():
    """When a key is absent in every loaded language, it is returned as-is.

    This guarantees the UI always shows *something* readable rather than
    an empty string or KeyError trace.
    """
    argus_i18n.init("fr")
    assert argus_i18n._("totally.unknown.key") == "totally.unknown.key"


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #


def test_format_kwargs():
    argus_i18n.init("en")
    out = argus_i18n._("vault.banner.detected", institution="BankCo")
    assert "BankCo" in out
    # Sanity: the placeholder itself must not leak into the output.
    assert "{institution}" not in out


def test_format_missing_kwarg_returns_template():
    """A missing placeholder argument should NOT crash the call."""
    argus_i18n.init("en")
    out = argus_i18n._("2fa.locked")  # no `seconds=` supplied
    # Template comes back unsubstituted — better than a traceback in UI.
    assert "{seconds}" in out


# --------------------------------------------------------------------------- #
# set_lang
# --------------------------------------------------------------------------- #


def test_set_lang_changes_lookup():
    argus_i18n.init("fr")
    assert argus_i18n._("mode.normal") == "Normal"

    argus_i18n.set_lang("es")
    assert argus_i18n.get_lang() == "es"
    # 'Normal' happens to be identical in fr/es — pick a key that differs.
    assert argus_i18n._("mode.private") == "Privado"


def test_set_lang_unknown_raises():
    argus_i18n.init("fr")
    with pytest.raises(ValueError):
        argus_i18n.set_lang("zz")


# --------------------------------------------------------------------------- #
# Locale auto-detect
# --------------------------------------------------------------------------- #


def test_auto_detect_locale_fallback_to_fr(monkeypatch):
    """Unknown system locale must fall back to French (project default)."""
    monkeypatch.setattr(argus_i18n.locale, "getlocale", lambda: ("zz_ZZ", "UTF-8"))
    argus_i18n.init()  # no explicit lang -> auto-detect
    assert argus_i18n.get_lang() == "fr"


def test_auto_detect_picks_english_locale(monkeypatch):
    monkeypatch.setattr(argus_i18n.locale, "getlocale", lambda: ("en_US", "UTF-8"))
    argus_i18n.init()
    assert argus_i18n.get_lang() == "en"


def test_auto_detect_handles_none_locale(monkeypatch):
    """``locale.getlocale`` can return ``(None, None)`` on minimal envs."""
    monkeypatch.setattr(argus_i18n.locale, "getlocale", lambda: (None, None))
    argus_i18n.init()
    assert argus_i18n.get_lang() == "fr"
