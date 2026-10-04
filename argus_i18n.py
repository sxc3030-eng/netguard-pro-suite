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
Argus i18n V1 — minimal JSON-backed translation loader.

The whole module is a thin layer over a per-language ``dict[str, str]``.
It loads every ``branding/argus/strings_*.json`` file once, keeps them in
process memory, and looks up keys with an ``fr -> en -> key`` fallback chain
(``fr`` is the project default — francophone author + French primary UX).

Public API
----------
``init(lang=None)`` loads the bundled ``strings_*.json`` files. Pass an
explicit ``lang`` to skip locale auto-detection.

``set_lang(lang)`` flips the active language at runtime; raises if the
target language wasn't loaded.

``get_lang()`` returns the active language code.

``_(key, **kwargs)`` looks the key up and returns the formatted string.
On miss, walks the fallback chain; if every tier misses, returns the key
itself unchanged (so the UI still shows *something* readable).

``available_langs()`` returns the language codes that ``init`` actually
managed to load (subset of ``["fr", "en", "es"]`` in V1).

Design notes
------------
* No dependency on Qt or any UI toolkit. Imports stay stdlib-only — this
  module is safe to import from CLI tools, tests, even surveillance.
* JSON files are loaded eagerly at ``init`` time, not lazily per-key:
  switching languages must not touch disk.
* Bracket-style ``str.format`` is used for placeholders. KeyError on a
  bad placeholder returns the raw template rather than crashing — UI
  stability beats strict-mode noise.
* Locale auto-detection uses ``locale.getlocale``; if the system locale
  starts with ``en`` we pick English, ``es`` -> Spanish, anything else
  falls through to French (the project default).
"""

from __future__ import annotations

import json
import locale
import logging
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------- #
# Module state
# --------------------------------------------------------------------------- #

_LOG = logging.getLogger(__name__)

# Ordered fallback chain. Project default is French; English is the
# universal fallback; Spanish trails because we don't expect to hit it
# in a fallback scenario but it's nice to be deterministic.
_FALLBACK = ["fr", "en", "es"]

_DEFAULT_LANG = "fr"

# lang code -> {key: translated string}
_strings: dict[str, dict[str, str]] = {}

# active language code (one of the loaded keys in ``_strings``).
_current_lang: str = _DEFAULT_LANG


def _strings_root() -> Path:
    """Resolve the directory holding ``strings_*.json`` files.

    Lives next to this module so that PyInstaller-frozen builds and
    in-tree dev runs both find it without env-var gymnastics.
    """
    return Path(__file__).resolve().parent / "branding" / "argus"


# --------------------------------------------------------------------------- #
# Locale auto-detection
# --------------------------------------------------------------------------- #


def _autodetect_lang() -> str:
    """Pick a language from the OS locale. Falls back to French.

    ``locale.getlocale`` can return ``(None, None)`` on a freshly-built
    venv — we treat that as 'fall back to fr'. We only inspect the first
    two characters of the language code so ``fr_CA``, ``fr_FR``, ``fr``
    all collapse to ``fr``.
    """
    try:
        lang_tuple = locale.getlocale()
        code = lang_tuple[0] if lang_tuple else None
    except Exception:
        # locale.getlocale can raise on weird LANG env values; never crash.
        code = None

    if not code:
        return _DEFAULT_LANG

    prefix = code[:2].lower()
    if prefix in _FALLBACK:
        return prefix
    return _DEFAULT_LANG


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def init(lang: Optional[str] = None) -> None:
    """Load every ``strings_<code>.json`` file under ``branding/argus/``.

    Idempotent: safe to call multiple times. The active language is set
    to ``lang`` if supplied, else auto-detected from the OS locale, with
    French as the ultimate fallback.

    Files that fail to parse are skipped with a warning rather than
    raising — a partially-localised app beats a crash.
    """
    global _current_lang, _strings

    root = _strings_root()
    loaded: dict[str, dict[str, str]] = {}

    for code in _FALLBACK:
        path = root / f"strings_{code}.json"
        if not path.exists():
            _LOG.warning("i18n: missing translation file %s", path.name)
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            _LOG.warning("i18n: failed to load %s: %s", path.name, exc)
            continue
        if not isinstance(data, dict):
            _LOG.warning("i18n: %s is not a JSON object — skipped", path.name)
            continue
        # Coerce every value to str — the JSON schema is documented as
        # flat str -> str, but a stray int or null shouldn't bring the UI
        # down.
        loaded[code] = {str(k): str(v) for k, v in data.items()}

    _strings = loaded

    # Choose the active language.
    if lang is None:
        lang = _autodetect_lang()
    if lang not in _strings:
        # Requested language not bundled — fall back to the first loaded
        # entry in the fallback chain, then ultimately to the default.
        for candidate in _FALLBACK:
            if candidate in _strings:
                lang = candidate
                break
        else:
            lang = _DEFAULT_LANG
    _current_lang = lang


def set_lang(lang: str) -> None:
    """Switch the active language. Raises ``ValueError`` if not loaded."""
    global _current_lang
    if lang not in _strings:
        raise ValueError(
            f"language {lang!r} is not loaded; call init() first or "
            f"choose one of {sorted(_strings.keys())}"
        )
    _current_lang = lang


def get_lang() -> str:
    """Return the active language code."""
    return _current_lang


def available_langs() -> list[str]:
    """Return the language codes that ``init`` successfully loaded."""
    return sorted(_strings.keys())


def _(key: str, **kwargs: object) -> str:
    """Look up ``key`` in the active language with fallback chain.

    Lookup order: active lang -> ``en`` -> ``fr`` -> the key itself.

    ``kwargs`` are passed through ``str.format``. If a placeholder is
    missing, the raw template is returned — never crash mid-render just
    because a caller forgot a substitution.
    """
    if not isinstance(key, str) or not key:
        return ""

    template: Optional[str] = None

    # 1. Active language.
    template = _strings.get(_current_lang, {}).get(key)
    # 2. English fallback (universal lingua franca for cybersec UIs).
    if template is None and "en" in _strings:
        template = _strings["en"].get(key)
    # 3. French fallback (project default).
    if template is None and "fr" in _strings:
        template = _strings["fr"].get(key)
    # 4. Last resort: the key itself, so the UI shows *something*.
    if template is None:
        template = key

    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError, ValueError):
        # Bad placeholder — log once at debug, return raw template.
        _LOG.debug("i18n: format failed for key %r kwargs=%r", key, kwargs)
        return template
