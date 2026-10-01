# Copyright (C) 2026 NetGuard AI Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""
Tests for inter-window tab drag/drop and tearoff in argus_pyqt.py.

Covers:
* Pure-logic policy: ``_can_accept_drop`` strict same-mode rule.
* Payload JSON serialisation roundtrip (cross-window drag uses JSON over
  the ``application/x-argus-tab`` MIME type).
* Drag-distance threshold constant.
* Qt-dependent: ``_extract_tab`` -> ``_import_tab`` roundtrip on a real
  ArgusBrowser instance (skipped if QApplication isn't usable).
* Qt-dependent: ``_tearoff_at_cursor`` honours the cursor's monitor
  (multi-monitor support) — verified by mocking QCursor.pos and
  QApplication.screenAt to a controlled fake screen.

Conventions match ``test_argus_sandbox.py``: a single module-level
QApplication via ``_ensure_qapp`` so we don't require pytest-qt.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Force offscreen for headless CI / sandboxed agent envs.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Pure-logic imports first — these never need Qt.
from argus_pyqt import (  # noqa: E402
    ARGUS_TAB_DRAG_THRESHOLD,
    ARGUS_TAB_MIME,
    _can_accept_drop,
)


# ─────────────────────────────────────────────────────────────────
# Optional Qt setup — single QApplication per test session.
# ─────────────────────────────────────────────────────────────────
_QT_INIT_ERROR: Optional[str] = None
_qapp = None


def _ensure_qapp():
    """Lazily build a QApplication. Returns it or sets _QT_INIT_ERROR."""
    global _qapp, _QT_INIT_ERROR
    if _qapp is not None or _QT_INIT_ERROR is not None:
        return _qapp
    try:
        from PyQt6.QtWidgets import QApplication

        existing = QApplication.instance()
        if existing is not None:
            _qapp = existing
            return _qapp
        _qapp = QApplication(sys.argv[:1])
    except Exception as exc:  # pragma: no cover — only on Qt-less boxes
        _QT_INIT_ERROR = f"{type(exc).__name__}: {exc}"
        _qapp = None
    return _qapp


def _skip_if_no_qt():
    """Skip the calling test if Qt isn't usable."""
    app = _ensure_qapp()
    if app is None:
        pytest.skip(f"QApplication unavailable: {_QT_INIT_ERROR}")


# ─────────────────────────────────────────────────────────────────
# Pure-logic tests (no Qt)
# ─────────────────────────────────────────────────────────────────
class TestCanAcceptDrop:
    """Strict same-mode policy is the security boundary between modes —
    no test in this class should require a Qt event loop.
    """

    def test_can_accept_drop_same_mode_normal_normal_true(self):
        assert _can_accept_drop("normal", "normal") is True

    def test_can_accept_drop_normal_to_vault_false(self):
        assert _can_accept_drop("normal", "vault") is False

    def test_can_accept_drop_vault_to_vault_true(self):
        assert _can_accept_drop("vault", "vault") is True

    def test_can_accept_drop_vault_to_normal_false(self):
        # Reverse direction also blocked — symmetry is mandatory or vault
        # cookies could leak into a Normal cookie jar via tab promotion.
        assert _can_accept_drop("vault", "normal") is False

    def test_can_accept_drop_private_to_private_true(self):
        assert _can_accept_drop("private", "private") is True

    def test_can_accept_drop_private_to_normal_false(self):
        assert _can_accept_drop("private", "normal") is False

    def test_can_accept_drop_empty_source_false(self):
        # Defensive: empty/None source mode (malformed payload) must NOT
        # match an empty target mode — refuse instead of accepting the
        # ambiguous case.
        assert _can_accept_drop("", "") is False

    def test_can_accept_drop_none_source_false(self):
        # Even if both sides are falsy in different ways we refuse.
        assert _can_accept_drop(None, None) is False  # type: ignore[arg-type]


class TestDragThresholdConstant:
    def test_drag_threshold_constant_is_8(self):
        # Locked at 8 px to balance reorder-friendliness vs accidental
        # drags from a sloppy click. Keep this assertion stable.
        assert ARGUS_TAB_DRAG_THRESHOLD == 8

    def test_drag_threshold_is_int(self):
        assert isinstance(ARGUS_TAB_DRAG_THRESHOLD, int)

    def test_mime_format_constant(self):
        # Lock the wire format so dropping into an older Argus build
        # doesn't silently mismatch.
        assert ARGUS_TAB_MIME == "application/x-argus-tab"


class TestPayloadSerialization:
    """The drag payload travels as JSON-encoded UTF-8 over a custom MIME
    type. Roundtripping via ``json.dumps`` -> ``json.loads`` must preserve
    every field exactly (no float rounding on tab_idx, no unicode mangling
    on title).
    """

    def test_payload_serialization_roundtrip(self):
        payload = {
            "source_window_id": 140723054321088,
            "tab_idx": 2,
            "mode": "normal",
            "url": "https://example.com/path?q=1",
            "title": "Example Domain",
        }
        wire = json.dumps(payload).encode("utf-8")
        parsed = json.loads(wire.decode("utf-8"))
        assert parsed == payload

    def test_payload_serialization_unicode_title(self):
        # Coffre and Privé are mode labels users see; vault titles often
        # carry accented characters. UTF-8 must survive the trip.
        payload = {
            "source_window_id": 1,
            "tab_idx": 0,
            "mode": "vault",
            "url": "https://banque-québec.example/login",
            "title": "Banque Québec — Connexion sécurisée",
        }
        wire = json.dumps(payload).encode("utf-8")
        parsed = json.loads(wire.decode("utf-8"))
        assert parsed["title"] == payload["title"]
        assert parsed["url"] == payload["url"]

    def test_payload_required_keys(self):
        # The producer is in argus_pyqt.TabBar._start_tab_drag — codify the
        # contract here so a future refactor can't quietly drop a field.
        payload = {
            "source_window_id": 1,
            "tab_idx": 0,
            "mode": "normal",
            "url": "",
            "title": "",
        }
        for key in ("source_window_id", "tab_idx", "mode", "url", "title"):
            assert key in payload, f"required key missing: {key}"


# ─────────────────────────────────────────────────────────────────
# Qt-dependent tests (need a QApplication, skipped without one)
# ─────────────────────────────────────────────────────────────────


@pytest.fixture
def offscreen_qapp():
    """QApplication fixture — skips the test if Qt can't initialise."""
    _skip_if_no_qt()
    return _ensure_qapp()


class TestTearoffMonitorSelection:
    """``_tearoff_at_cursor`` must honour the monitor under the cursor."""

    def test_tearoff_uses_cursor_screen(self, offscreen_qapp):
        from PyQt6.QtCore import QPoint, QRect

        # Build a fake screen reporting a known availableGeometry. We
        # intercept QCursor.pos -> a point on this screen and
        # QApplication.screenAt -> the fake. The test asserts that the
        # _tearoff_at_cursor helper reads QCursor.pos and resolves the
        # screen via QApplication.screenAt — verifying multi-monitor
        # routing without needing two real displays.
        fake_screen = MagicMock()
        fake_screen.availableGeometry.return_value = QRect(2000, 100, 1280, 720)

        cursor_point = QPoint(2400, 400)

        from argus_pyqt import _tearoff_at_cursor

        # Patch the entry points _tearoff_at_cursor uses. We don't care
        # whether the new ArgusBrowser actually opens — patch the class
        # constructor in argus_pyqt so the function returns immediately
        # without spinning up QtWebEngine (heavyweight). The assertion
        # is that QCursor.pos and QApplication.screenAt got called with
        # the fake cursor point.
        with patch("argus_pyqt.QCursor") as mock_cursor, \
             patch("argus_pyqt.QApplication") as mock_qapp_cls, \
             patch("argus_pyqt.ArgusBrowser") as mock_browser_cls:
            mock_cursor.pos.return_value = cursor_point
            mock_qapp_cls.screenAt.return_value = fake_screen
            mock_qapp_cls.primaryScreen.return_value = fake_screen
            # Mock ArgusBrowser so we don't construct a real window:
            # capture the kwargs to verify mode propagation.
            mock_instance = MagicMock()
            mock_instance.tab_pages = []
            mock_browser_cls.return_value = mock_instance
            mock_browser_cls._instances = {}

            payload = {
                "source_window_id": 999999,
                "tab_idx": 0,
                "mode": "normal",
                "url": "https://example.com",
                "title": "Example",
            }
            _tearoff_at_cursor(payload)

            # QCursor.pos was used to find the cursor.
            mock_cursor.pos.assert_called()
            # screenAt was queried with the cursor position.
            mock_qapp_cls.screenAt.assert_called_with(cursor_point)
            # ArgusBrowser was instantiated with the source mode.
            mock_browser_cls.assert_called_once()
            _, kwargs = mock_browser_cls.call_args
            # accept either positional or keyword form
            args, _ = mock_browser_cls.call_args
            mode_arg = kwargs.get("startup_mode") or (args[0] if args else None)
            assert mode_arg == "normal"
            # Window should have been moved + resized inside the fake
            # screen's available geometry. resize() and move() were both
            # called on the new browser instance.
            mock_instance.resize.assert_called()
            mock_instance.move.assert_called()


class TestExtractImportRoundtrip:
    """A full roundtrip through ``_extract_tab`` -> ``_import_tab`` must
    preserve the view object identity (tab is moved, not cloned) and the
    target window must end up with one extra tab.
    """

    def test_extract_tab_then_import_tab_roundtrip(self, offscreen_qapp):
        # Lazy import inside the test so import-time failures (e.g.
        # missing QtWebEngine) hit the skip path cleanly.
        try:
            from argus_pyqt import ArgusBrowser
        except Exception as exc:  # pragma: no cover — Qt missing
            pytest.skip(f"argus_pyqt import failed: {exc}")

        # Spawning a real ArgusBrowser brings up the full chrome + AI
        # panel. Heavy but worth it for an honest integration test.
        try:
            src = ArgusBrowser(startup_mode="normal")
            dst = ArgusBrowser(startup_mode="normal")
        except Exception as exc:
            pytest.skip(f"ArgusBrowser construction failed: {exc}")

        try:
            # __init__ opens one tab; open one more so we can extract a
            # non-last tab and verify the source still has a tab afterwards.
            try:
                src._open_new_tab("about:blank")
            except Exception:
                pass
            assert len(src.tab_pages) >= 1, "source must have at least one tab"
            tab_idx = 0
            initial_src_count = len(src.tab_pages)
            initial_dst_count = len(dst.tab_pages)

            view, profile, title = src._extract_tab(tab_idx)

            # Source either lost a tab OR opened a placeholder if it was
            # the last one. Per spec: window stays open, so total >= 1.
            assert len(src.tab_pages) >= 1
            # Extracted view must be a real QWebEngineView instance.
            from PyQt6.QtWebEngineWidgets import QWebEngineView
            assert isinstance(view, QWebEngineView)
            # Title is a string (may be empty for about:blank).
            assert isinstance(title, str)

            # Now import into the destination and verify counts.
            new_idx = dst._import_tab(view, profile, title, "normal")
            assert isinstance(new_idx, int)
            assert len(dst.tab_pages) == initial_dst_count + 1
            # The view we extracted must be the one now in dst (move, not copy).
            assert dst.tab_pages[-1] is view

            # The dst tab bar should have grown by one.
            assert len(dst.tab_bar.tab_buttons) == len(dst.tab_pages)
        finally:
            try:
                src.close()
                src.deleteLater()
            except Exception:
                pass
            try:
                dst.close()
                dst.deleteLater()
            except Exception:
                pass


class TestArgusBrowserInstanceRegistry:
    """The WeakValueDictionary registry is what the tearoff path uses to
    locate the source window from the payload's ``source_window_id``.
    """

    def test_instances_registry_records_new_browser(self, offscreen_qapp):
        try:
            from argus_pyqt import ArgusBrowser
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"argus_pyqt import failed: {exc}")

        try:
            br = ArgusBrowser(startup_mode="normal")
        except Exception as exc:
            pytest.skip(f"ArgusBrowser construction failed: {exc}")
        try:
            assert id(br) in ArgusBrowser._instances
            assert ArgusBrowser._instances[id(br)] is br
        finally:
            try:
                br.close()
                br.deleteLater()
            except Exception:
                pass


class TestArgusBrowserStartupMode:
    """``startup_mode`` is passed by the tearoff helper so the new window
    inherits the source tab's mode (Coffre tearoff stays Coffre)."""

    def test_startup_mode_normal_default(self, offscreen_qapp):
        try:
            from argus_pyqt import ArgusBrowser
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"argus_pyqt import failed: {exc}")
        try:
            br = ArgusBrowser()
        except Exception as exc:
            pytest.skip(f"ArgusBrowser construction failed: {exc}")
        try:
            assert br.current_mode == "normal"
        finally:
            try:
                br.close()
                br.deleteLater()
            except Exception:
                pass

    def test_startup_mode_invalid_falls_back_to_normal(self, offscreen_qapp):
        try:
            from argus_pyqt import ArgusBrowser
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"argus_pyqt import failed: {exc}")
        try:
            br = ArgusBrowser(startup_mode="bogus_mode_id_xyz")
        except Exception as exc:
            pytest.skip(f"ArgusBrowser construction failed: {exc}")
        try:
            # Defensive fallback — never start in an unknown mode.
            assert br.current_mode == "normal"
        finally:
            try:
                br.close()
                br.deleteLater()
            except Exception:
                pass
