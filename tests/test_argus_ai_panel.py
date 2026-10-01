# Copyright (C) 2026 NetGuard AI Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""Tests for the Argus AI side panel — direct-BYOK providers + slash
commands + worker mode selection.

Conventions match the existing test suite (test_argus_tab_drag.py):

* No real Qt widget construction unless gated by ``_skip_if_no_qt``.
* No real network. Provider tests monkeypatch ``urllib.request.urlopen``.
* No real on-disk writes outside ``tmp_path``.
* Each test is independent — settings JSON is rebuilt per test.

Coverage
--------
* ``parse_slash_commands`` — the small parser that strips leading
  ``/url``/``/selection``/``/screenshot`` tokens. Exercises the
  "command must be at the start of the message" rule because that's the
  injection-resistance contract.
* Settings I/O — load/save round-trip + ``has_any_api_key`` env-var path.
* AnthropicProvider / OpenAIProvider / GoogleProvider — happy path on
  blocking ``call`` with a mocked HTTP response.
* AIChatWorker mode picker — direct vs server based on settings/env.
* AISettingsDialog (Qt) — opens, persists keys to the configured path.
"""

from __future__ import annotations

import io
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

import argus_ai_providers as ai_providers  # noqa: E402


# --------------------------------------------------------------------------- #
# Optional Qt setup — single QApplication per test session.
# --------------------------------------------------------------------------- #
_QT_INIT_ERROR: Optional[str] = None
_qapp = None


def _ensure_qapp():
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
    except Exception as exc:  # pragma: no cover
        _QT_INIT_ERROR = f"{type(exc).__name__}: {exc}"
        _qapp = None
    return _qapp


def _skip_if_no_qt():
    app = _ensure_qapp()
    if app is None:
        pytest.skip(f"QApplication unavailable: {_QT_INIT_ERROR}")


# --------------------------------------------------------------------------- #
# Pure-logic: slash command parsing
# --------------------------------------------------------------------------- #


class TestParseSlashCommands:
    """Slash commands must be at the START of the message and are
    consumed in order. A non-recognized first token aborts extraction
    even if a recognized one follows — this is the injection-resistance
    contract: a model output containing ``/url`` mid-text shouldn't
    rewrite a follow-up user message."""

    def test_no_command(self):
        cmds, residual = ai_providers.parse_slash_commands("hello world")
        assert cmds == []
        assert residual == "hello world"

    def test_single_url(self):
        cmds, residual = ai_providers.parse_slash_commands("/url summarize")
        assert cmds == ["/url"]
        assert residual == "summarize"

    def test_two_commands_same_order(self):
        cmds, residual = ai_providers.parse_slash_commands("/url /selection compare")
        assert cmds == ["/url", "/selection"]
        assert residual == "compare"

    def test_three_commands(self):
        cmds, residual = ai_providers.parse_slash_commands("/url /selection /screenshot")
        assert cmds == ["/url", "/selection", "/screenshot"]
        assert residual == ""

    def test_command_in_middle_not_extracted(self):
        # Critical: a /url in the middle is NOT extracted (otherwise the
        # model could trick the panel into pulling URL context post-hoc).
        cmds, residual = ai_providers.parse_slash_commands("hello /url world")
        assert cmds == []
        assert residual == "hello /url world"

    def test_unknown_command_first_blocks(self):
        # Even if a recognized cmd follows, an unknown first token stops
        # the parse — protects against adjacent typo / future commands.
        cmds, residual = ai_providers.parse_slash_commands("/foo /url x")
        assert cmds == []
        assert residual == "/foo /url x"

    def test_leading_whitespace_stripped(self):
        cmds, residual = ai_providers.parse_slash_commands("   /url   hi")
        assert cmds == ["/url"]
        assert residual == "hi"

    def test_empty_input(self):
        cmds, residual = ai_providers.parse_slash_commands("")
        assert cmds == []
        assert residual == ""


# --------------------------------------------------------------------------- #
# Settings I/O
# --------------------------------------------------------------------------- #


class TestSettingsIO:
    def test_load_missing_file_returns_empty(self, tmp_path):
        target = tmp_path / "ai_settings.json"
        # File doesn't exist — must return {} not raise.
        assert ai_providers.load_settings(target) == {}

    def test_save_then_load_roundtrip(self, tmp_path):
        target = tmp_path / "ai_settings.json"
        payload = {
            "provider": "openai",
            "providers": {"openai": {"api_key": "sk-test", "model": "gpt-4o"}},
        }
        ai_providers.save_settings(payload, target)
        assert target.exists()
        # File must be valid JSON, not pickled or otherwise mangled.
        on_disk = json.loads(target.read_text(encoding="utf-8"))
        assert on_disk == payload
        # Loader returns a dict equal in shape (idempotency check).
        assert ai_providers.load_settings(target) == payload

    def test_load_corrupt_json_returns_empty(self, tmp_path):
        target = tmp_path / "ai_settings.json"
        target.write_text("{not valid json", encoding="utf-8")
        # Don't crash on bad files — return empty so first-launch flow
        # behaves like a fresh install.
        assert ai_providers.load_settings(target) == {}

    def test_has_any_api_key_with_env_var(self, monkeypatch):
        # Strip any pre-existing keys.
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                  "GOOGLE_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        # No env, no settings — False.
        assert ai_providers.has_any_api_key({}) is False
        # OPENAI_API_KEY env var alone = True.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        assert ai_providers.has_any_api_key({}) is True

    def test_has_any_api_key_with_settings_only(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                  "GOOGLE_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        settings = {"providers": {"google": {"api_key": "AIza-test"}}}
        assert ai_providers.has_any_api_key(settings) is True

    def test_has_any_api_key_empty_string_doesnt_count(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                  "GOOGLE_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        # Empty string in settings shouldn't be treated as configured.
        settings = {"providers": {"anthropic": {"api_key": "   "}}}
        assert ai_providers.has_any_api_key(settings) is False


# --------------------------------------------------------------------------- #
# Provider HTTP — mocked urllib
# --------------------------------------------------------------------------- #


def _mock_response(body: dict, status: int = 200):
    """Build a fake urllib.request.urlopen() context manager returning
    JSON-encoded ``body`` and ``status``."""
    raw = json.dumps(body).encode("utf-8")

    class FakeResp:
        def __init__(self):
            self.status = status

        def read(self):
            return raw

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return FakeResp()


class TestAnthropicProvider:
    """The provider's ``call`` is the one path that ships in v1
    regardless of streaming support — must work for the non-streaming
    fallback when the panel can't open SSE for some reason."""

    def test_blocking_call_returns_text(self, monkeypatch):
        provider = ai_providers.AnthropicProvider()
        body = {
            "content": [{"type": "text", "text": "Bonjour."}],
            "usage": {"input_tokens": 5, "output_tokens": 2},
            "model": "claude-sonnet-4-6",
        }
        monkeypatch.setattr(
            "argus_ai_providers.urllib.request.urlopen",
            lambda req, timeout=120: _mock_response(body),
        )
        result = provider.call(
            messages=[{"role": "user", "content": "Salut"}],
            system="", model="claude-sonnet-4-6",
            api_key="sk-ant-test",
        )
        assert result["ok"] is True
        assert result["reply"] == "Bonjour."
        assert result["tokens_in"] == 5
        assert result["tokens_out"] == 2
        assert result["provider"] == "anthropic"

    def test_call_http_400_returns_error(self, monkeypatch):
        import urllib.error

        provider = ai_providers.AnthropicProvider()

        def fake_urlopen(req, timeout=120):
            raise urllib.error.HTTPError(
                req.full_url, 401, "Unauthorized", {},
                io.BytesIO(b'{"error":{"message":"bad key"}}'),
            )

        monkeypatch.setattr(
            "argus_ai_providers.urllib.request.urlopen", fake_urlopen
        )
        result = provider.call(
            messages=[{"role": "user", "content": "x"}],
            system="", model="claude-sonnet-4-6",
            api_key="bad",
        )
        assert result["ok"] is False
        assert "http_401" in result["error"]


class TestOpenAIProvider:
    def test_blocking_call_returns_text(self, monkeypatch):
        provider = ai_providers.OpenAIProvider()
        body = {
            "choices": [{"message": {"content": "Hi."}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1},
            "model": "gpt-4o",
        }
        monkeypatch.setattr(
            "argus_ai_providers.urllib.request.urlopen",
            lambda req, timeout=120: _mock_response(body),
        )
        result = provider.call(
            messages=[{"role": "user", "content": "yo"}],
            system="be brief", model="gpt-4o",
            api_key="sk-test",
        )
        assert result["ok"] is True
        assert result["reply"] == "Hi."
        assert result["tokens_in"] == 3
        assert result["tokens_out"] == 1


class TestGoogleProvider:
    def test_blocking_call_returns_text(self, monkeypatch):
        provider = ai_providers.GoogleProvider()
        body = {
            "candidates": [
                {"content": {"parts": [{"text": "Hola."}]}}
            ],
            "usageMetadata": {"promptTokenCount": 2, "candidatesTokenCount": 1},
        }
        monkeypatch.setattr(
            "argus_ai_providers.urllib.request.urlopen",
            lambda req, timeout=120: _mock_response(body),
        )
        result = provider.call(
            messages=[{"role": "user", "content": "hola"}],
            system="", model="gemini-2.0-flash",
            api_key="AIza-test",
        )
        assert result["ok"] is True
        assert result["reply"] == "Hola."
        assert result["provider"] == "google"

    def test_supports_streaming_false(self):
        # Locked: Gemini ships blocking only in v1 (see module docstring).
        # If this changes, update _on_provider_changed flow expectations.
        assert ai_providers.GoogleProvider().supports_streaming is False


# --------------------------------------------------------------------------- #
# Provider key resolution
# --------------------------------------------------------------------------- #


class TestProviderKeyResolution:
    def test_env_var_takes_precedence(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY",):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
        provider = ai_providers.AnthropicProvider()
        # Settings has a different key — env wins.
        settings = {"providers": {"anthropic": {"api_key": "from-settings"}}}
        assert provider.get_api_key(settings) == "from-env"

    def test_settings_used_when_no_env(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        provider = ai_providers.AnthropicProvider()
        settings = {"providers": {"anthropic": {"api_key": "from-settings"}}}
        assert provider.get_api_key(settings) == "from-settings"

    def test_no_key_returns_none(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        provider = ai_providers.AnthropicProvider()
        assert provider.get_api_key({}) is None

    def test_get_model_falls_back_to_default(self, monkeypatch):
        provider = ai_providers.OpenAIProvider()
        assert provider.get_model({}) == provider.default_model

    def test_get_model_respects_settings(self):
        provider = ai_providers.OpenAIProvider()
        settings = {"providers": {"openai": {"model": "gpt-4o-mini"}}}
        assert provider.get_model(settings) == "gpt-4o-mini"


# --------------------------------------------------------------------------- #
# AIChatWorker mode picker
# --------------------------------------------------------------------------- #


class TestAIChatWorkerModePicker:
    """The worker decides direct-BYOK vs server-backend based on whether
    ANY API key is configured. Verified at the unit level so we don't
    depend on Qt being importable."""

    def _make_worker(self, monkeypatch, **kwargs):
        # Import inside the test so monkeypatched env vars apply.
        import argus_pyqt
        return argus_pyqt.AIChatWorker(messages=[], **kwargs)

    def test_force_direct_overrides(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                  "GOOGLE_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        w = self._make_worker(monkeypatch, force_mode="direct")
        assert w._pick_mode() == "direct"

    def test_force_server_overrides(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        w = self._make_worker(monkeypatch, force_mode="server")
        assert w._pick_mode() == "server"

    def test_no_keys_picks_server(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY",
                  "GOOGLE_API_KEY", "GEMINI_API_KEY"):
            monkeypatch.delenv(k, raising=False)
        # Patch settings loader so the worker doesn't see a real
        # ai_settings.json on the test box.
        monkeypatch.setattr(
            ai_providers, "load_settings", lambda path=None: {}
        )
        w = self._make_worker(monkeypatch)
        assert w._pick_mode() == "server"

    def test_env_key_picks_direct(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        w = self._make_worker(monkeypatch)
        assert w._pick_mode() == "direct"


# --------------------------------------------------------------------------- #
# AISettingsDialog (Qt-dependent)
# --------------------------------------------------------------------------- #


class TestAISettingsDialog:
    """Open the dialog, type a key, click Save, verify the JSON file got
    the new key. Skipped on boxes without Qt."""

    def test_save_persists_keys(self, tmp_path, monkeypatch):
        _skip_if_no_qt()
        # Redirect the providers' default settings path into tmp_path so
        # we don't pollute argus_data/ on the dev box.
        target = tmp_path / "ai_settings.json"
        monkeypatch.setattr(ai_providers, "DEFAULT_SETTINGS_PATH", target)

        import argus_pyqt
        dlg = argus_pyqt.AISettingsDialog()
        # Set a key for OpenAI and switch default provider to OpenAI.
        dlg._key_edits["openai"].setText("sk-from-test")
        # Move to OpenAI in the default-provider combo.
        for i in range(dlg._default_combo.count()):
            if dlg._default_combo.itemData(i) == "openai":
                dlg._default_combo.setCurrentIndex(i)
                break
        dlg._save_and_close()
        # Saved file must reflect the input.
        assert target.exists()
        on_disk = json.loads(target.read_text(encoding="utf-8"))
        assert on_disk["provider"] == "openai"
        assert on_disk["providers"]["openai"]["api_key"] == "sk-from-test"
        dlg.deleteLater()

    def test_dialog_loads_existing_keys(self, tmp_path, monkeypatch):
        _skip_if_no_qt()
        target = tmp_path / "ai_settings.json"
        target.write_text(json.dumps({
            "provider": "google",
            "providers": {"google": {"api_key": "AIza-existing",
                                       "model": "gemini-1.5-pro"}},
        }), encoding="utf-8")
        monkeypatch.setattr(ai_providers, "DEFAULT_SETTINGS_PATH", target)

        import argus_pyqt
        dlg = argus_pyqt.AISettingsDialog()
        # The default-provider combo should be on Google.
        assert dlg._default_combo.currentData() == "google"
        # Model combo for Google should reflect persisted choice.
        assert dlg._model_combos["google"].currentText() == "gemini-1.5-pro"
        dlg.deleteLater()


# --------------------------------------------------------------------------- #
# AIPanel slash-command flow (Qt-dependent)
# --------------------------------------------------------------------------- #


class TestAIPanelSlashCommands:
    """End-to-end of the slash-command resolution loop, mocking out the
    network worker. Ensures the panel correctly dispatches /url +
    /selection + /screenshot before launching the worker."""

    def test_url_only_command_dispatches(self, tmp_path, monkeypatch):
        _skip_if_no_qt()
        # Stub the history file so we don't write into argus_data/.
        monkeypatch.setattr(
            "argus_pyqt.AI_HISTORY_FILE", tmp_path / "h.json"
        )
        # Block the actual worker — we only care that _launch_worker
        # was called with an enriched message.
        launches: list[list[dict]] = []
        import argus_pyqt
        monkeypatch.setattr(
            argus_pyqt.AIPanel, "_launch_worker",
            lambda self, msgs: launches.append(msgs),
        )
        history = argus_pyqt.AIHistoryManager(tmp_path / "h.json")
        panel = argus_pyqt.AIPanel(history)
        panel.set_page_provider(lambda: ("https://example.com/foo", None))

        # Type a /url command and trigger the send.
        panel.input.setPlainText("/url summarize this page")
        panel._send_clicked()

        assert len(launches) == 1
        last_user = launches[0][-1]["content"]
        assert "[Slash context]" in last_user
        assert "https://example.com/foo" in last_user
        assert "summarize this page" in last_user
        # Original /url token should NOT remain in the residual sent to
        # the model — it's been consumed by the resolver.
        assert "/url" not in last_user.split("[/Slash context]")[-1]

        panel.deleteLater()

    def test_no_command_uses_legacy_path(self, tmp_path, monkeypatch):
        _skip_if_no_qt()
        monkeypatch.setattr(
            "argus_pyqt.AI_HISTORY_FILE", tmp_path / "h.json"
        )
        # Capture the legacy capture-and-send path.
        captured: list[str] = []
        import argus_pyqt
        monkeypatch.setattr(
            argus_pyqt.AIPanel, "_capture_page_and_send",
            lambda self, text: captured.append(text),
        )
        history = argus_pyqt.AIHistoryManager(tmp_path / "h.json")
        panel = argus_pyqt.AIPanel(history)
        panel.input.setPlainText("hello world")
        panel._send_clicked()
        assert captured == ["hello world"]
        panel.deleteLater()


# --------------------------------------------------------------------------- #
# Module-level invariants
# --------------------------------------------------------------------------- #


class TestModuleInvariants:
    """Smoke tests that lock the public surface of argus_ai_providers so
    the AI panel keeps importing across refactors."""

    def test_providers_registry_complete(self):
        assert set(ai_providers.PROVIDERS.keys()) == {
            "anthropic", "openai", "google",
        }

    def test_each_provider_has_required_attrs(self):
        for name, p in ai_providers.PROVIDERS.items():
            assert p.name == name, f"{name}: name field mismatch"
            assert p.label, f"{name}: missing label"
            assert p.default_model, f"{name}: missing default_model"
            assert p.models, f"{name}: empty models list"
            assert p.env_keys, f"{name}: empty env_keys"

    def test_get_provider_unknown_falls_back(self):
        # Unknown name → anthropic. This is the safety net the panel
        # depends on when ai_settings.json contains a stale provider key.
        assert ai_providers.get_provider("nonexistent").name == "anthropic"

    def test_known_slash_commands_locked(self):
        # Locks the contract — adding a command requires updating the
        # panel's resolver too. Don't change this without the resolver.
        assert ai_providers.KNOWN_SLASH_COMMANDS == (
            "/url", "/selection", "/screenshot",
        )
